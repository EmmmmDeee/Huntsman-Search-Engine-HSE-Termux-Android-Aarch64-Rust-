//! Independent lookup work run at once.
//!
//! Each job runs on a thread of its own, with the stack `serve` gives a lookup. The caller reads
//! every answer back in the order it gave the jobs, so it folds them exactly as it did when they
//! ran one after another. A lookup then takes as long as its slowest job, not the sum of them all.
//!
//! A job whose thread cannot be started runs on the calling thread instead, so a phone short of
//! threads still gets every answer, only later. A job that panics panics the caller once every
//! other job has finished, as it would have done had it run there.

use std::panic::resume_unwind;
use std::sync::{Mutex, PoisonError};
use std::thread::{self, Scope, ScopedJoinHandle};

/// A lookup does TLS and JSON decoding, so each job gets the stack `serve` gives a lookup.
pub const JOB_STACK_BYTES: usize = 4 * 1024 * 1024;

/// One piece of work for [`all`].
pub type Job<'env, R> = Box<dyn FnOnce() -> R + Send + 'env>;

/// A job waiting for its thread. A thread that cannot be started drops the closure it was given,
/// so the job waits here: its thread takes it out, or the caller does when the thread never ran.
type Slot<'env, R> = Mutex<Option<Job<'env, R>>>;

/// Runs every job at once and answers their results in the order of `jobs`.
#[must_use]
pub fn all<'env, R: Send + 'env>(jobs: Vec<Job<'env, R>>) -> Vec<R> {
    let slots: Vec<Slot<'env, R>> = jobs.into_iter().map(|job| Mutex::new(Some(job))).collect();
    thread::scope(|scope| {
        let running: Vec<_> = slots.iter().map(|slot| start(scope, slot)).collect();
        running
            .into_iter()
            .zip(&slots)
            .map(|(handle, slot)| finish(handle, slot))
            .collect()
    })
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
}
