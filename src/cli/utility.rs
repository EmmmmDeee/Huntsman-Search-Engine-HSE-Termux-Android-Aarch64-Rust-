//! Binary adapter commands. Business logic stays in the library crate.

use std::process::ExitCode;

use super::fail;
use huntsman_recon::au_id::{Identifier, classify as classify_id};
use huntsman_recon::classify::classify_response;
use huntsman_recon::exit::{EX_DATAERR, EX_USAGE};
use huntsman_recon::geohash;
use huntsman_recon::geoint::{haversine_m, parse_latlon};
use huntsman_recon::redact::coarsen_latlon;
use huntsman_recon::source_outcome::{classify_fetch, recommended_action};

pub(super) fn geo(args: &[String]) -> ExitCode {
    let [a, b] = args else {
        return fail(EX_USAGE, "usage: huntsman-recon geo LAT,LON LAT,LON");
    };
    let Ok((lat1, lon1)) = parse_latlon(a) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {a}"));
    };
    let Ok((lat2, lon2)) = parse_latlon(b) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {b}"));
    };
    println!("{:.0}", haversine_m(lat1, lon1, lat2, lon2));
    ExitCode::SUCCESS
}

pub(super) fn geohash_cmd(args: &[String]) -> ExitCode {
    // A hash on its own, with no comma, is decoded to the cell it names.
    if let [hash] = args {
        if !hash.contains(',') {
            return geohash_decode(hash);
        }
    }
    let (pair, precision) = match args {
        [pair] => (pair, None),
        [pair, precision] => (pair, Some(precision.as_str())),
        _ => {
            return fail(
                EX_USAGE,
                "usage: huntsman-recon geohash LAT,LON [PRECISION] | geohash HASH",
            );
        }
    };
    let Ok((lat, lon)) = parse_latlon(pair) else {
        return fail(EX_DATAERR, &format!("bad coordinate: {pair}"));
    };
    let precision = match precision.map(str::parse::<usize>) {
        None => 7,
        Some(Ok(p)) => p,
        Some(Err(_)) => return fail(EX_DATAERR, "bad precision"),
    };
    match geohash::encode(lat, lon, precision) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

/// The cell a geohash names: its centre, then its bounds, one `key=value` per line.
fn geohash_decode(hash: &str) -> ExitCode {
    match geohash::decode(&hash.trim().to_ascii_lowercase()) {
        Ok(cell) => {
            let (lat, lon) = cell.center();
            println!(
                "center={lat:.8},{lon:.8}\nlat_min={:.8}\nlat_max={:.8}\nlon_min={:.8}\nlon_max={:.8}",
                cell.lat_min, cell.lat_max, cell.lon_min, cell.lon_max
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(EX_DATAERR, &e.to_string()),
    }
}

pub(super) fn coarsen_cmd(args: &[String]) -> ExitCode {
    let [pair] = args else {
        return fail(EX_USAGE, "usage: huntsman-recon coarsen LAT,LON");
    };
    match coarsen_latlon(pair) {
        Some(coarse) => {
            println!("{coarse}");
            ExitCode::SUCCESS
        }
        None => fail(EX_DATAERR, &format!("bad coordinate: {pair}")),
    }
}

/// The rest of the line is the token, so `id 53 004 085 616` reads as it does quoted.
pub(super) fn id_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon id TOKEN...");
    }
    match classify_id(&args.join(" ")) {
        Ok(Identifier::Abn { bare, acn }) => {
            println!("abn={bare}");
            println!("acn={}", acn.as_deref().unwrap_or("none"));
        }
        Ok(Identifier::Acn { bare }) => println!("acn={bare}"),
        Ok(Identifier::Bsb { bare, institution }) => {
            println!("bsb={bare}");
            println!("institution={}", institution.unwrap_or("unknown"));
        }
        Err(e) => return fail(EX_DATAERR, &e.to_string()),
    }
    ExitCode::SUCCESS
}

/// The rest of the line is the body, so an unquoted body is classified whole, not by its first word.
pub(super) fn classify(args: &[String]) -> ExitCode {
    let [status, body @ ..] = args else {
        return fail(EX_USAGE, "usage: huntsman-recon classify STATUS BODY...");
    };
    if body.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon classify STATUS BODY...");
    }
    let body = body.join(" ");
    let Ok(status) = status.parse::<u16>() else {
        return fail(EX_DATAERR, "bad status");
    };
    let kind = classify_fetch(status, &body);
    println!("{:?}", classify_response(status, &body));
    println!("outcome={}", kind.as_str());
    println!("action={}", recommended_action(kind).as_str());
    ExitCode::SUCCESS
}
