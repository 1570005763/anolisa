//! Task proposals retry once when the draft fails Cedar syntax, Strict typing or a path literal
//! check, with the local reason in the second payload; unsupported features are never retried.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use asc_intent::{
    PolicyError, ProposalContext, ProposalError, ProposalOutcome, TaskInput, propose_task,
};
use asc_model_client::provider::{ModelProvider, ProviderError};
use serde_json::json;

const VALID: &str = r#"permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" || resource.path like "/srv/demo/out/*" };"#;
const SYNTAX: &str = r#"permit(principal action == SecCore::Action::"file.write", resource);"#;
const UNTYPED: &str = r#"permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.missing == "/srv/demo/out" };"#;
const WILDCARD: &str = r#"permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out/*" };"#;
const UNSUPPORTED: &str = r#"@reason("demo")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#;

fn body(policy: &str) -> String {
    json!({"policy": policy, "unresolved": []}).to_string()
}

struct Scripted {
    responses: Mutex<VecDeque<Result<String, ProviderError>>>,
    payloads: Mutex<Vec<String>>,
}

impl ModelProvider for Scripted {
    fn complete(
        &self,
        _: &str,
        _: &str,
        payload: &str,
        _: Instant,
    ) -> Result<String, ProviderError> {
        self.payloads.lock().unwrap().push(payload.to_owned());
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ProviderError::Transport))
    }
}

fn propose(
    responses: Vec<Result<String, ProviderError>>,
) -> (Result<ProposalOutcome, ProposalError>, Vec<String>) {
    let provider = Scripted {
        responses: Mutex::new(responses.into()),
        payloads: Mutex::new(Vec::new()),
    };
    let outcome = propose_task(
        &provider,
        "fixture",
        &TaskInput {
            source_id: "source".into(),
            text: "Build locally".into(),
        },
        &ProposalContext::new("task-1".into(), 2_000_000_000, 1800).unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    (outcome, provider.payloads.into_inner().unwrap())
}

#[test]
fn a_rejected_draft_is_repaired_by_one_retry() {
    for (first, reason) in [
        (SYNTAX, "syntax is invalid"),
        (UNTYPED, "failed Cedar validation"),
        (WILDCARD, "equality compares a concrete path"),
    ] {
        let (outcome, payloads) = propose(vec![Ok(body(first)), Ok(body(VALID))]);
        let Ok(ProposalOutcome::Candidate { candidate }) = outcome else {
            panic!("expected a candidate after the retry of {first}");
        };
        assert_eq!(candidate.policy_text(), VALID);
        assert_eq!(payloads.len(), 2);
        assert!(!payloads[0].contains("上次输出被本地校验拒绝"));
        assert!(payloads[1].contains("上次输出被本地校验拒绝"));
        assert!(payloads[1].contains(reason), "{}", payloads[1]);
    }
}

#[test]
fn a_persistent_rejection_keeps_its_outcome_after_the_retry() {
    let (outcome, payloads) = propose(vec![Ok(body(SYNTAX)), Ok(body(SYNTAX))]);
    assert!(matches!(
        outcome,
        Err(ProposalError::Policy(PolicyError::Syntax))
    ));
    assert_eq!(payloads.len(), 2);

    let (outcome, payloads) = propose(vec![Ok(body(UNTYPED)), Ok(body(UNTYPED))]);
    assert!(matches!(
        outcome,
        Err(ProposalError::Policy(PolicyError::Validation))
    ));
    assert_eq!(payloads.len(), 2);

    let (outcome, payloads) = propose(vec![Ok(body(WILDCARD)), Ok(body(WILDCARD))]);
    assert!(matches!(
        outcome,
        Ok(ProposalOutcome::NeedsClarification { .. })
    ));
    assert_eq!(payloads.len(), 2);
}

#[test]
fn a_failed_retry_call_fails_the_proposal() {
    let (outcome, payloads) = propose(vec![Ok(body(SYNTAX)), Err(ProviderError::Transport)]);
    assert!(matches!(outcome, Err(ProposalError::Intent(_))));
    assert_eq!(payloads.len(), 2);
}

#[test]
fn unsupported_features_and_valid_drafts_are_not_retried() {
    let (outcome, payloads) = propose(vec![Ok(body(UNSUPPORTED)), Ok(body(VALID))]);
    assert!(matches!(
        outcome,
        Ok(ProposalOutcome::NeedsClarification { .. })
    ));
    assert_eq!(payloads.len(), 1);

    let (outcome, payloads) = propose(vec![Ok(body(VALID))]);
    assert!(matches!(outcome, Ok(ProposalOutcome::Candidate { .. })));
    assert_eq!(payloads.len(), 1);
}
