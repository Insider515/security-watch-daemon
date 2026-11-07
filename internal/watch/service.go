// Assembling the service: what it consists of and what gets started. Kept out
// of main so the startup path can be read and tested in parts.
package watch

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// Service is the assembled service: the event emission point, the watchers and
// everything they need.
type Service struct {
	cfg   *Config
	sinks *MultiSink
	emit  func(Event)

	chain     *Chain
	deduper   *Deduper
	enricher  *Enricher
	filter    *Filter
	blocklist *Blocklist
	dossier   *DossierStore
	actors    *ActorStore
	baseline  *Baseline
	selfGuard *SelfGuard
	metrics   *Metrics

	access    *AccessWatcher
	auth      *AuthWatcher
	appLog    *AppLogWatcher
	audit     *AuditWatcher
	files     *FilesWatcher
	ports     *PortsWatcher
	processes *ProcessWatcher
	resources *ResourcesWatcher
	db        *DBWatcher
	mirror    *MirrorServer
	trap      *TrapServer

	// Events from the watchers go through a queue and are processed one at a
	// time. Two reasons: the chain numbers then match the order of the records
	// in the file (an event born while another one is being processed used to
	// land in the file before it), and the sinks are written to from a single
	// goroutine.
	//
	// The processing goroutine is started by NewService and stopped by Close, so
	// there is always a reader: a watcher that emits more events than the queue
	// holds waits for the reader instead of deadlocking.
	queue    chan Event
	stop     context.CancelFunc
	stopped  chan struct{}
	handleMu sync.Mutex
}

// NewService assembles the service from the configuration. Assembly order:
// first what event emission depends on (repeat merging, address facts, the
// chain, the proposal list), then emission itself, then the watchers.
func NewService(cfg *Config, configPath string) (*Service, error) {
	service := &Service{cfg: cfg}

	service.metrics = NewMetrics(cfg.StateDir)
	service.sinks = NewMultiSink(cfg.Sinks, cfg.Host, cfg.StateDir)
	if service.sinks.Empty() {
		slog.Warn("no sink is enabled: events will only go to the service log")
	}
	service.chain = NewChain(cfg.StateDir)
	service.deduper = NewDeduper(cfg.DedupWindow.Duration, cfg.DedupIgnoreSubject)
	service.enricher = NewEnricher(cfg.Enrich)
	service.filter = NewFilter(cfg.Ignore, cfg.SeverityOverrides)
	service.dossier = NewDossierStore(cfg.StateDir)
	service.blocklist = NewBlocklist(cfg.Blocking, cfg.StateDir, func(e Event) { slog.Info("action", slog.String("event", e.String())) })
	service.queue = make(chan Event, 10000)
	service.emit = service.enqueue

	service.actors = NewActorStore(cfg.Actors, cfg.StateDir, service.emit)
	service.baseline = NewBaseline(cfg.Baseline, cfg.StateDir, service.emit)
	service.selfGuard = NewSelfGuard(cfg.Self, configPath, service.emit)

	canary := NewRuntimeCanary(NewCanary(cfg.Canary))
	service.access = NewAccessWatcher(cfg.Access, canary, service.emit)
	service.auth = NewAuthWatcher(cfg.Auth, service.emit)
	service.appLog = NewAppLogWatcher(cfg.AppLog, canary, service.emit)
	service.audit = NewAuditWatcher(cfg.Audit, service.emit)
	service.files = NewFilesWatcher(cfg.Files, cfg.StateDir, service.emit)
	service.ports = NewPortsWatcher(cfg.Ports, service.emit)
	service.processes = NewProcessWatcher(cfg.Processes, service.emit)
	service.resources = NewResourcesWatcher(cfg.Resources, service.emit)
	service.mirror = NewMirrorServer(cfg.Mirror, canary, service.emit)
	service.trap = NewTrapServer(cfg.Trap, service.dossier, canary, service.emit)

	db, err := NewDBWatcher(cfg.DB, cfg.StateDir, service.emit)
	if err != nil {
		return nil, err
	}
	service.db = db

	ctx, cancel := context.WithCancel(context.Background())
	service.stop = cancel
	service.stopped = make(chan struct{})
	go func() {
		defer close(service.stopped)
		service.process(ctx)
	}()
	return service, nil
}

// Close releases the connections and writes the counters, so they are visible to
// the -stats command after a short run and after a shutdown.
func (s *Service) Close() {
	s.waitQueue()
	if s.stop != nil {
		s.stop()
		<-s.stopped
	}
	s.sinks.Flush()
	if s.db != nil {
		s.db.Close()
	}
	s.metrics.Save()
}

// waitQueue waits until the queue is empty and the event being processed is
// finished. Used where the result has to be on disk before returning: -once and
// shutdown. The lock is what makes it reliable: while an event is being handled
// the lock is held, so an empty queue seen under the lock means everything has
// been written.
func (s *Service) waitQueue() {
	for {
		s.handleMu.Lock()
		empty := len(s.queue) == 0
		s.handleMu.Unlock()
		if empty {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// enqueue is what the watchers call. It only puts the event into the queue, so
// an event emitted while another one is being processed does not jump ahead of
// it. A full queue blocks the watcher: slowing down reading is better than
// losing events.
func (s *Service) enqueue(event Event) {
	if event.At.IsZero() {
		event.At = time.Now()
	}
	s.queue <- event
}

// drain processes everything the queue holds right now, including the events
// born while processing. Called by the processing goroutine when it stops, so
// nothing is left behind.
func (s *Service) drain() {
	for {
		select {
		case event := <-s.queue:
			s.handleEvent(event)
		default:
			return
		}
	}
}

// process handles the queue until ctx is cancelled, then drains what is left.
func (s *Service) process(ctx context.Context) {
	for {
		select {
		case event := <-s.queue:
			s.handleEvent(event)
		case <-ctx.Done():
			s.drain()
			return
		}
	}
}

// handleEvent is the single processing point for an event: suppression, merging
// repeats, address facts, chain stamping, accounting and delivery to the
// sinks. It runs in one goroutine at a time.
func (s *Service) handleEvent(event Event) {
	s.handleMu.Lock()
	defer s.handleMu.Unlock()

	if event.At.IsZero() {
		event.At = time.Now()
	}
	s.metrics.Seen()
	filtered, keep := s.filter.Apply(event)
	if !keep {
		s.metrics.Ignored()
		return
	}
	ready, send := s.deduper.Offer(filtered)
	if !send {
		s.metrics.Merged()
		return
	}
	ready = s.enricher.Apply(ready)
	ready = s.chain.Stamp(ready)
	s.blocklist.Consider(ready)

	// A used canary token is linked to whoever it was issued to: that proves the
	// one who poked at the trap and the one trying to log in are the same.
	if token := ready.Details["token"]; token != "" {
		if owner := s.dossier.MarkBaitUsed(token); owner != nil && owner.IP != ready.IP {
			ready.Details["bait_issued_to"] = owner.IP
		}
	}
	s.actors.Observe(ready)
	s.baseline.Observe(ready)

	// The grade is worked out here, once, so that every sink - the file, the
	// webhook, the bot - sees the same figure. It is raised by what has piled
	// up from the address, which is why it comes after the actor store.
	score := s.actors.ScoreOf(ready.IP)
	ready.Grade = EscalateByScore(GradeOf(ready, s.cfg.GradeOverrides), score, s.actors.AlertScore())
	if score > 0 {
		if ready.Details == nil {
			ready.Details = map[string]string{}
		}
		ready.Details["actor_score"] = strconv.Itoa(score)
	}

	logEvent(ready)
	if err := s.sinks.Send([]Event{ready}); err != nil {
		s.metrics.SinkError()
	}
	s.metrics.Sent(ready)
}

// ScanOnce performs a single pass with the watchers that work by scanning. It is
// meant for checking the configuration without continuous watching.
func (s *Service) ScanOnce() {
	if s.cfg.Files.Enabled {
		if err := s.files.Scan(); err != nil {
			slog.Error("file scan", slog.Any("error", err))
		}
	}
	if s.cfg.Resources.Enabled {
		s.resources.Scan()
	}
	if s.cfg.Ports.Enabled {
		s.ports.Scan()
	}
	if s.cfg.Processes.Enabled {
		s.processes.Scan()
	}
	if s.cfg.DB.Enabled {
		s.db.Scan()
	}
	s.waitQueue()
}

// Run starts watching and keeps working until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup

	s.startTailers(ctx, &wg)
	s.startScanners(ctx, &wg)
	s.startServers(ctx, &wg)
	s.startHousekeeping(ctx, &wg)

	if s.cfg.Baseline.Enabled {
		if learning, left := s.baseline.Learning(); learning {
			slog.Info("learning normal behaviour is in progress",
				slog.String("remaining", left.Round(time.Hour).String()))
		}
	}
	if s.cfg.Self.Enabled {
		s.selfGuard.Started(s.cfg.Host, s.sinks.Name())
		s.startSelfGuard(ctx, &wg)
	}
	s.startBot(ctx, &wg)
	s.sinks.RetryPending(ctx, s.cfg.Sinks.OutboxRetry.Duration)

	slog.Info("watching started", slog.String("server", s.cfg.Host), slog.String("sinks", s.sinks.Name()))
	<-ctx.Done()
	wg.Wait()
}

// Stopped reports the service shutdown when self-protection is enabled.
func (s *Service) Stopped(reason string) {
	if s.cfg.Self.Enabled {
		s.selfGuard.Stopped(reason)
	}
}

// startTailers starts reading the logs.
func (s *Service) startTailers(ctx context.Context, wg *sync.WaitGroup) {
	type source struct {
		enabled bool
		path    string
		name    string
		handle  func(string)
	}
	for _, item := range []source{
		{s.cfg.Access.Enabled, s.cfg.Access.Path, "web server log", s.access.Handle},
		{s.cfg.Auth.Enabled, s.cfg.Auth.Path, "auth log", s.auth.Handle},
		{s.cfg.AppLog.Enabled, s.cfg.AppLog.Path, "application log", s.appLog.Handle},
		{s.cfg.Audit.Enabled, s.cfg.Audit.Path, "auditd log", s.audit.Handle},
	} {
		if !item.enabled || item.path == "" {
			continue
		}
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			tailer := NewTailer(item.path, s.cfg.StateDir, time.Second)
			if err := tailer.Run(ctx, item.handle); err != nil {
				slog.Error("log reading interrupted", slog.String("source", item.name), slog.Any("error", err))
			}
		}()
	}
}

// startScanners starts the watchers that scan on schedule.
func (s *Service) startScanners(ctx context.Context, wg *sync.WaitGroup) {
	type scanner struct {
		enabled  bool
		interval time.Duration
		action   func()
	}
	for _, item := range []scanner{
		{s.cfg.Files.Enabled && len(s.cfg.Files.Paths) > 0, s.cfg.Files.Interval.Duration, func() {
			if err := s.files.Scan(); err != nil {
				slog.Error("file scan", slog.Any("error", err))
			}
		}},
		{s.cfg.Ports.Enabled, s.cfg.Ports.Interval.Duration, s.ports.Scan},
		{s.cfg.Processes.Enabled, s.cfg.Processes.Interval.Duration, s.processes.Scan},
		{s.cfg.Resources.Enabled, s.cfg.Resources.Interval.Duration, s.resources.Scan},
		{s.cfg.DB.Enabled && (len(s.cfg.DB.Checks) > 0 || len(s.cfg.DB.ColumnWatches) > 0),
			s.cfg.DB.Interval.Duration, s.db.Scan},
		{s.cfg.Archive.Enabled, s.cfg.Archive.Interval.Duration, func() {
			RunArchive(s.cfg.Archive, s.cfg.Sinks.File, s.emit)
		}},
	} {
		if !item.enabled {
			continue
		}
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			runEvery(ctx, item.interval, item.action)
		}()
	}

	// Watching files the moment they change. Scheduled scanning stays in place:
	// it survives a service restart and sees what happened while it was down.
	if s.cfg.Files.Enabled && len(s.cfg.Files.Paths) > 0 && s.cfg.Realtime {
		wg.Add(1)
		go func() {
			defer wg.Done()
			realtime := NewRealtimeFiles(s.cfg.Files, s.emit)
			if err := realtime.Run(ctx); err != nil {
				slog.Warn("real-time watching is unavailable", slog.Any("reason", err))
			}
		}()
	}
}

// startServers brings up the mirror receiver and the trap.
func (s *Service) startServers(ctx context.Context, wg *sync.WaitGroup) {
	if s.cfg.Mirror.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.mirror.Run(ctx); err != nil {
				slog.Error("mirror receiver", slog.Any("error", err))
			}
		}()
	}
	if s.cfg.Trap.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.trap.Run(ctx); err != nil {
				slog.Error("trap", slog.Any("error", err))
			}
		}()
	}
}

// startHousekeeping starts counter cleanup and the periodic digest.
func (s *Service) startHousekeeping(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		runEvery(ctx, time.Minute, func() {
			now := time.Now()
			s.access.Sweep(now)
			s.auth.Sweep(now)
			s.deduper.Forget(24 * time.Hour)
			s.audit.Flush(5 * time.Second)
			s.metrics.Save()
		})
	}()

	if s.cfg.Actors.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runEvery(ctx, s.cfg.Actors.DigestInterval.Duration, func() {
				s.actors.Digest()
				s.actors.Forget()
			})
		}()
	}
}

// startSelfGuard starts the own-file check and the heartbeat.
func (s *Service) startSelfGuard(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		runEvery(ctx, s.cfg.Self.CheckInterval.Duration, s.selfGuard.Check)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The heartbeat: on the receiving side its absence is an alarm.
		ticker := time.NewTicker(s.cfg.Self.HeartbeatInterval.Duration)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq, head := s.chain.Head()
				s.selfGuard.Heartbeat(seq, head, s.metrics.Details())
			}
		}
	}()
}

// startBot starts taking commands from the operator in Telegram. The bot works
// over what the service already keeps - the same actors, the same block list -
// so the chat and the command line show one and the same state.
func (s *Service) startBot(ctx context.Context, wg *sync.WaitGroup) {
	sink := s.sinks.Telegram()
	if sink == nil || !s.cfg.Sinks.Telegram.Commands {
		return
	}
	bot := NewBot(s.cfg.Sinks.Telegram, s.cfg.Host, sink,
		s.actors, s.blocklist, s.dossier, s.metrics)
	wg.Add(1)
	go func() {
		defer wg.Done()
		bot.Run(ctx)
	}()
}

// runEvery repeats the action at the given interval until ctx is cancelled.
func runEvery(ctx context.Context, every time.Duration, action func()) {
	if every <= 0 {
		every = time.Minute
	}
	action()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			action()
		}
	}
}
