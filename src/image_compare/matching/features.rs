use super::super::photo::MIN_SIDE;
use super::pixels::{Alignment, Score, pixel_agreement};
use image::{GrayImage, imageops};
use imageproc::{
    binary_descriptors::{
        BinaryDescriptor,
        brief::{BriefDescriptor, TestPair, brief},
    },
    corners::corners_fast9,
    point::Point,
};

struct Level {
    scale: f32,
    features: Vec<BriefDescriptor>,
}

fn test_pairs() -> Vec<TestPair> {
    let mut seed: u32 = 853_164_112;
    let mut coordinate = || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        2 + (seed >> 16) % 27
    };
    (0..256)
        .map(|_| TestPair {
            p0: Point::new(coordinate(), coordinate()),
            p1: Point::new(coordinate(), coordinate()),
        })
        .collect()
}

// Image planes are at most 896 pixels per side, with positive scales no greater than one.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn levels(image: &GrayImage, pairs: &Vec<TestPair>) -> Vec<Level> {
    let mut levels = Vec::new();
    for scale in [1.0f32, 0.80, 0.64, 0.51, 0.41, 0.33] {
        let width = (image.width() as f32 * scale).round() as u32;
        let height = (image.height() as f32 * scale).round() as u32;
        if width < MIN_SIDE || height < MIN_SIDE {
            break;
        }
        let plane = imageops::resize(image, width, height, imageops::FilterType::Triangle);
        let mut corners = corners_fast9(&plane, 18);
        corners.sort_unstable_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.y.cmp(&b.y))
                .then(a.x.cmp(&b.x))
        });
        let mut used = vec![false; ((width / 12 + 1) * (height / 12 + 1)) as usize];
        let points: Vec<_> = corners
            .into_iter()
            .filter_map(|c| {
                if c.x < 18 || c.y < 18 || c.x + 18 >= width || c.y + 18 >= height {
                    return None;
                }
                let cell = (c.y / 12 * (width / 12 + 1) + c.x / 12) as usize;
                if std::mem::replace(&mut used[cell], true) {
                    return None;
                }
                Some(Point::new(c.x, c.y))
            })
            .take(420)
            .collect();
        let features = brief(&plane, &points, 256, Some(pairs))
            .map(|(features, _)| features)
            .unwrap_or_default();
        levels.push(Level { scale, features });
    }
    levels
}

#[derive(Clone, Copy)]
struct Match {
    x: f32,
    y: f32,
    u: f32,
    v: f32,
    distance: u32,
}

// Corner coordinates are bounded by the image plane and are exactly representable.
#[allow(clippy::cast_precision_loss)]
fn matches(a: &Level, b: &Level) -> Vec<Match> {
    let mut nearest_b = vec![(u32::MAX, usize::MAX); b.features.len()];
    let mut best_a = Vec::with_capacity(a.features.len());
    for (i, feature) in a.features.iter().enumerate() {
        let (mut best, mut runner_up, mut j_best) = (u32::MAX, u32::MAX, usize::MAX);
        for (j, other) in b.features.iter().enumerate() {
            let dist = feature.hamming_distance(other);
            if dist < nearest_b[j].0 {
                nearest_b[j] = (dist, i);
            }
            if dist < best {
                runner_up = best;
                best = dist;
                j_best = j;
            } else {
                runner_up = runner_up.min(dist);
            }
        }
        best_a.push((best, runner_up, j_best));
    }
    let mut matches: Vec<_> = best_a
        .into_iter()
        .enumerate()
        .filter_map(|(i, (best, next, j))| {
            if best > 64 || next == u32::MAX || best * 100 >= next * 88 || nearest_b[j].1 != i {
                return None;
            }
            let p = a.features[i].position();
            let q = b.features[j].position();
            Some(Match {
                x: (p.x as f32 + 0.5) / a.scale,
                y: (p.y as f32 + 0.5) / a.scale,
                u: (q.x as f32 + 0.5) / b.scale,
                v: (q.y as f32 + 0.5) / b.scale,
                distance: best,
            })
        })
        .collect();
    matches.sort_by_key(|m| m.distance);
    matches
}

pub(super) fn local_match(a: &GrayImage, b: &GrayImage) -> Option<(usize, Score)> {
    let pairs = test_pairs();
    let levels_a = levels(a, &pairs);
    let levels_b = levels(b, &pairs);
    for la in &levels_a {
        for lb in &levels_b {
            let matches = matches(la, lb);
            let Some((hits, transform)) =
                best_alignment(&matches, la.scale / lb.scale, 2.5 / lb.scale)
            else {
                continue;
            };
            let score = pixel_agreement(a, b, transform);
            if score.accepts(10.0, 0.88) {
                return Some((hits, score));
            }
        }
    }
    None
}

// Keep trial hypotheses in the same deterministic order as the descriptor matches.
fn best_alignment(matches: &[Match], ratio: f32, tolerance: f32) -> Option<(usize, Alignment)> {
    const MIN_INLIERS: usize = 12;
    if matches.len() < MIN_INLIERS {
        return None;
    }

    let mut best: Option<(usize, Alignment)> = None;
    let mut inliers = Vec::with_capacity(matches.len());
    let samples = &matches[..matches.len().min(40)];
    for (i, p) in samples.iter().enumerate() {
        for q in &samples[i + 1..] {
            let (x, y) = (q.x - p.x, q.y - p.y);
            let distance_squared = x * x + y * y;
            if distance_squared < 3600.0 {
                continue;
            }

            let scale = (x * (q.u - p.u) + y * (q.v - p.v)) / distance_squared;
            if !(0.75..=1.35).contains(&(scale / ratio)) {
                continue;
            }

            let (dx, dy) = (p.u - scale * p.x, p.v - scale * p.y);
            inliers.clear();
            inliers.extend(matches.iter().filter(|m| {
                (m.u - scale * m.x - dx).abs() <= tolerance
                    && (m.v - scale * m.y - dy).abs() <= tolerance
            }));
            if inliers.len() < MIN_INLIERS || best.is_some_and(|(count, _)| count >= inliers.len())
            {
                continue;
            }
            if let Some(transform) = refine(&inliers) {
                best = Some((inliers.len(), transform));
            }
        }
    }
    best
}

#[allow(clippy::many_single_char_names)] // x/y and u/v are paired coordinates.
fn refine(points: &[&Match]) -> Option<Alignment> {
    let (mut x, mut y, mut u, mut v) = (0.0, 0.0, 0.0, 0.0);
    let (mut min_x, mut max_x, mut min_y, mut max_y) = (
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::INFINITY,
        f32::NEG_INFINITY,
    );
    for p in points {
        x += p.x;
        y += p.y;
        u += p.u;
        v += p.v;
        min_x = min_x.min(p.x);
        min_y = min_y.min(p.y);
        max_x = max_x.max(p.x);
        max_y = max_y.max(p.y);
    }
    if max_x - min_x < 65.0 || max_y - min_y < 65.0 {
        return None;
    }
    let n = f32::from(u16::try_from(points.len()).ok()?);
    let (x, y, u, v) = (x / n, y / n, u / n, v / n);
    let (mut covariance, mut variance) = (0.0, 0.0);
    for p in points {
        let (dx, dy) = (p.x - x, p.y - y);
        covariance += dx * (p.u - u) + dy * (p.v - v);
        variance += dx * dx + dy * dy;
    }
    let scale = covariance / variance;
    Some(Alignment {
        sx: scale,
        sy: scale,
        dx: u - scale * x,
        dy: v - scale * y,
    })
}
