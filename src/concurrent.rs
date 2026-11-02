//! Independent lookup work on a bounded number of scoped threads.
//!
//! `all` retains input-order results, but at most `MAX_PARALLEL_JOBS` workers run per call.
//! Free workers take the next job rather than waiting for a slow provider to complete.
//! Every job runs once, including when the OS refuses thread creation; job panics are
//! delivered to the caller only after the remaining jobs have finished.
//!
//! `pair` retains its two-way concurrency and thread-failure fallback.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread::{self, Scope, ScopedJoinHandle};

/// A lookup does TLS and JSON decoding, so each job gets the stack `serve` gives a lookup.
pub const JOB_STACK_BYTES: usize = 4 * 1024 * 1024;

/// One piece of work for [`all`].
pub type Job<'env, R> = Box<dyn FnOnce() -> R + Send + 'env>;

/// A job waiting for its thread. A thread that cannot be started drops the closure it was given,
/// so the job waits here: its thread takes it out, or the caller does when the thread never ran.
type Slot<'env, R> = Mutex<Option<Job<'env, R>>>;

/// Maximum scoped lookup workers per call. At 4 MiB per worker this bounds
/// requested worker-stack reservations to 64 MiB, independently of provider count.
/// It is not a process-wide cap on simultaneous HTTP requests across callers.
pub const MAX_PARALLEL_JOBS: usize = 16;

/// Runs all jobs on a bounded, work-conserving worker pool and returns answers in
/// input order. If no worker can be started, runs every job on the calling thread.
/// A job panic is rethrown after *all* jobs finish, without cancelling queued work.
#[must_use]
pub fn all<'env, R: Send + 'env>(jobs: Vec<Job<'env, R>>) -> Vec<R> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let slots: Vec<Slot<'env, R>> = jobs.into_iter().map(|job| Mutex::new(Some(job))).collect();
    let results: Vec<Mutex<Option<thread::Result<R>>>> =
        (0..slots.len()).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..slots.len().min(MAX_PARALLEL_JOBS) {
            match thread::Builder::new()
                .name("lookup-job".into())
                .stack_size(JOB_STACK_BYTES)
                .spawn_scoped(scope, || drain(&slots, &results, &next))
            {
                Ok(handle) => workers.push(handle),
                Err(_) => break,
            }
        }
        if workers.is_empty() {
            drain(&slots, &results, &next);
        }
        for worker in workers {
            worker.join().unwrap_or_else(|panic| resume_unwind(panic));
        }
    });
    results
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .expect("each queued lookup must run")
                .unwrap_or_else(|panic| resume_unwind(panic))
        })
        .collect()
}

/// Workers claim distinct job indices without serialising network calls on a queue lock.
/// Catch a job panic so one failed provider cannot strand unstarted jobs.
fn drain<'env, R: Send + 'env>(
    slots: &[Slot<'env, R>],
    results: &[Mutex<Option<thread::Result<R>>>],
    next: &AtomicUsize,
) {
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        let Some(slot) = slots.get(index) else {
            break;
        };
        if let Some(job) = take(slot) {
            let outcome = catch_unwind(AssertUnwindSafe(job));
            *results[index]
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(outcome);
        }
    }
}

/// Runs `a` and `b` at once, `a` on a thread of its own and `b` on this one, and answers both.
pub fn pair<'env, A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send + 'env,
    RA: Send + 'env,
    B: FnOnce() -> RB,
{
    let slot: Slot<'env, RA> = Mutex::new(Some(Box::new(a)));
    thread::scope(|scope| {
        let handle = start(scope, &slot);
        let b = b();
        (finish(handle, &slot), b)
    })
}

fn take<'env, R>(slot: &Slot<'env, R>) -> Option<Job<'env, R>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// The job in `slot` started on a thread of its own, or `None` when no thread could be had.
fn start<'scope, 'env, R: Send + 'env>(
    scope: &'scope Scope<'scope, '_>,
    slot: &'scope Slot<'env, R>,
) -> Option<ScopedJoinHandle<'scope, Option<R>>> {
    thread::Builder::new()
        .name("lookup-job".into())
        .stack_size(JOB_STACK_BYTES)
        .spawn_scoped(scope, move || take(slot).map(|job| job()))
        .ok()
}

/// The answer of the job in `slot`: from its thread, or run here when its thread never started.
fn finish<R>(handle: Option<ScopedJoinHandle<'_, Option<R>>>, slot: &Slot<'_, R>) -> R {
    let ran = handle.and_then(|handle| handle.join().unwrap_or_else(|panic| resume_unwind(panic)));
    match ran.or_else(|| take(slot).map(|job| job())) {
        Some(answer) => answer,
        None => unreachable!("a job runs on its own thread or on the caller's"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;
    use std::time::{Duration, Instant};

    /// Holds every caller until `want` callers are inside together, or the wait runs out; answers
    /// whether they all were.
    struct Meeting {
        inside: Mutex<usize>,
        arrived: Condvar,
        want: usize,
    }

    impl Meeting {
        fn new(want: usize) -> Self {
            Self {
                inside: Mutex::new(0),
                arrived: Condvar::new(),
                want,
            }
        }

        fn meet(&self) -> bool {
            let mut inside = self.inside.lock().unwrap_or_else(PoisonError::into_inner);
            *inside += 1;
            self.arrived.notify_all();
            let until = Instant::now() + Duration::from_secs(5);
            while *inside < self.want {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return false;
                }
                inside = self
                    .arrived
                    .wait_timeout(inside, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            true
        }
    }

    #[test]
    fn every_job_runs_at_the_same_time_and_answers_in_the_order_given() {
        let meeting = Meeting::new(4);
        let jobs: Vec<Job<'_, (usize, bool)>> = (0..4_usize)
            .map(|i| {
                let meeting = &meeting;
                Box::new(move || (i, meeting.meet())) as Job<'_, (usize, bool)>
            })
            .collect();
        assert_eq!(
            all(jobs),
            vec![(0, true), (1, true), (2, true), (3, true)],
            "each job saw the other three running"
        );
    }

    #[test]
    fn a_pair_runs_both_at_the_same_time_and_answers_each_in_its_place() {
        let meeting = Meeting::new(2);
        let (a, b) = pair(|| ("a", meeting.meet()), || ("b", meeting.meet()));
        assert_eq!((a, b), (("a", true), ("b", true)));
        let nested = pair(|| 1, || pair(|| 2, || 3));
        assert_eq!(nested, (1, (2, 3)));
    }

    #[test]
    fn a_job_whose_thread_never_started_runs_on_the_caller() {
        let slot: Slot<'_, &str> = Mutex::new(Some(Box::new(|| "ran here")));
        assert_eq!(finish(None, &slot), "ran here");
    }

    #[test]
    fn a_job_that_panics_panics_the_caller_after_the_others_finish() {
        let finished = Mutex::new(false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let failing: Job<'_, ()> = Box::new(|| panic!("this job failed"));
            all(vec![
                failing,
                Box::new(|| {
                    std::thread::sleep(Duration::from_millis(50));
                    *finished.lock().unwrap_or_else(PoisonError::into_inner) = true;
                }),
            ])
        }));
        assert!(outcome.is_err(), "the panic reached the caller");
        assert!(
            *finished.lock().unwrap_or_else(PoisonError::into_inner),
            "the other job was not cut short"
        );
    }
    #[test]
    fn bounded_workers_run_every_job_once_and_preserve_input_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let completed = AtomicUsize::new(0);
        let jobs: Vec<Job<'_, usize>> = (0..96)
            .map(|index| {
                let active = &active;
                let peak = &peak;
                let completed = &completed;
                Box::new(move || {
                    let running = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(running, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(2));
                    active.fetch_sub(1, Ordering::SeqCst);
                    completed.fetch_add(1, Ordering::SeqCst);
                    index
                }) as Job<'_, usize>
            })
            .collect();
        let result = all(jobs);
        assert_eq!(result, (0..96).collect::<Vec<_>>());
        assert_eq!(completed.load(Ordering::SeqCst), 96);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(peak.load(Ordering::SeqCst) <= MAX_PARALLEL_JOBS);
    }

    #[test]
    fn panicking_job_does_not_cancel_queued_jobs() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let completed = AtomicUsize::new(0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut jobs: Vec<Job<'_, ()>> = vec![Box::new(|| panic!("provider panic"))];
            for _ in 0..40 {
                let completed = &completed;
                jobs.push(Box::new(move || {
                    completed.fetch_add(1, Ordering::SeqCst);
                }));
            }
            all(jobs)
        }));
        assert!(outcome.is_err(), "provider failure must reach caller");
        assert_eq!(completed.load(Ordering::SeqCst), 40);
    }

}
