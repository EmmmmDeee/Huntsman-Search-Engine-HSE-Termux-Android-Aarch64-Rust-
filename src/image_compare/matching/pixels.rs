use image::GrayImage;

#[derive(Clone, Copy)]
pub(super) struct Alignment {
    pub sx: f32,
    pub sy: f32,
    pub dx: f32,
    pub dy: f32,
}

pub(super) struct Score {
    mean_error: f32,
    agreement: f32,
    texture: f32,
    coverage: f32,
}

impl Score {
    pub(super) fn accepts(&self, max_error: f32, min_agreement: f32) -> bool {
        self.coverage >= 0.04
            && self.texture >= 4.0
            && self.mean_error <= max_error
            && self.agreement >= min_agreement
    }

    pub(super) fn describe(&self) -> String {
        format!(
            "Mean grayscale difference {:.1}/255. {:.0}% of sampled overlap within 20 levels.",
            self.mean_error,
            self.agreement * 100.0
        )
    }
}

// The sampler checks both axes before conversion. The plane fits within 896 × 896.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn bilinear(image: &GrayImage, x: f32, y: f32) -> f32 {
    let x0 = x.floor() as u32;
    let y0 = y.floor() as u32;
    let fx = x - x0 as f32;
    let fy = y - y0 as f32;
    let row = |y| {
        f32::from(image.get_pixel(x0, y)[0]) * (1.0 - fx)
            + f32::from(image.get_pixel(x0 + 1, y)[0]) * fx
    };
    row(y0) * (1.0 - fy) + row(y0 + 1) * fy
}

// Plane dimensions and sample counts fit exactly in the f32 mantissa.
#[allow(clippy::cast_precision_loss, clippy::many_single_char_names)]
pub(super) fn pixel_agreement(a: &GrayImage, b: &GrayImage, t: Alignment) -> Score {
    let (mut count, mut close, mut total, mut texture) = (0u32, 0u32, 0.0, 0.0);
    let step = (a.width().max(a.height()) / 190).max(2);
    for y in (2..a.height().saturating_sub(2)).step_by(step as usize) {
        for x in (2..a.width().saturating_sub(2)).step_by(step as usize) {
            let u = (x as f32 + 0.5) * t.sx + t.dx - 0.5;
            let v = (y as f32 + 0.5) * t.sy + t.dy - 0.5;
            if u < 1.0 || v < 1.0 || u >= b.width() as f32 - 2.0 || v >= b.height() as f32 - 1.0 {
                continue;
            }
            let l = f32::from(a.get_pixel(x, y)[0]);
            let delta = (l - bilinear(b, u, v)).abs();
            count += 1;
            close += u32::from(delta <= 20.0);
            total += delta;
            texture += (l - f32::from(a.get_pixel(x + 2, y)[0])).abs();
        }
    }
    let samples = count.max(1) as f32;
    Score {
        mean_error: total / samples,
        agreement: close as f32 / samples,
        texture: texture / samples,
        coverage: count as f32 * (step * step) as f32 / (a.width() * a.height()) as f32,
    }
}
