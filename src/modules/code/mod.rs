//! Developer-platform footprint — source-code hosting, package registries,
//! and CI/identity providers a subject leaves a trail on.
//!
//! Grouped from the flat module list so the ~18 code-forge / package-index
//! sources read as one discipline. `github_api` stays `pub(crate)` — it is the
//! shared GitHub REST client the three GitHub sources build on, not a
//! registered module of its own.

pub(crate) mod github_api;

pub mod bitbucket_user;
pub mod codeberg_user;
pub mod cpan_user;
pub mod crates_io;
pub mod dockerhub_user;
pub mod gitea_user;
pub mod github_code_search;
pub mod github_commits;
pub mod github_user;
pub mod gitlab_user;
pub mod hexpm_user;
pub mod huggingface_user;
pub mod launchpad_user;
pub mod npm_author;
pub mod pypi_user;
pub mod rubygems_user;
pub mod sourceforge_user;
