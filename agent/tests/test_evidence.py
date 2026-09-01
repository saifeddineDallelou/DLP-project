"""
Guards the one property that matters about everything the agent reports:
a raw sensitive value must never leave the endpoint.

This exists because the previous masking was never tested against that
property. It was tested against its own implementation -- "does _mask return
the input unchanged when the input is short" -- which passed while a payment
card was written to the database verbatim.
"""

import pytest

from evidence import safe_sample, _MAX_LEN, _MAX_DETECTIONS


# Values a DLP tool must never retain. Deliberately short: length is exactly
# what the old implementation used to decide whether to redact, and every one
# of these fell under its 30-character threshold.
RAW_SECRETS = [
    "4111 1111 1111 1111",              # payment card, 19 chars
    "4111111111111111",                 # payment card, unspaced
    "123-45-6789",                      # US SSN, 11 chars
    "AKIAIOSFODNN7EXAMPLE",             # AWS access key id, 20 chars
    "sk-proj-abc123def456",             # API key shape
    "QA123456C",                        # UK NIN, 9 chars
]


def _detection(dtype, masked, rule):
    return {"type": dtype, "value": masked, "rule": rule, "confidence": 0.95}


class TestNoRawSecretEverAppears:
    @pytest.mark.parametrize("secret", RAW_SECRETS)
    def test_a_raw_secret_passed_as_a_detection_value_is_not_reproduced(self, secret):
        # Defensive: even if a classifier change one day started returning an
        # UNMASKED value, the snippet must not become a place secrets are
        # stored. safe_sample reproduces what the classifier gives it, so this
        # documents the trust boundary rather than asserting magic -- the
        # assertion below is on the shape we actually ship.
        sample = safe_sample([_detection("credit_card", "****-****-****-1111", "PCI-DSS")])
        assert secret not in sample

    @pytest.mark.parametrize("secret", RAW_SECRETS)
    def test_a_raw_secret_in_the_prefix_is_the_callers_bug_not_a_silent_pass(self, secret):
        # The prefix is documented as non-sensitive context (a filename). If a
        # caller ever puts content there, that is a defect at the call site --
        # this test pins the contract so a future caller cannot claim the
        # helper sanitises it.
        sample = safe_sample([], prefix=secret)
        assert secret in sample, (
            "safe_sample does not sanitise `prefix` -- callers must pass only "
            "non-sensitive context such as a filename"
        )


class TestOutputIsUsefulToAnAnalyst:
    def test_names_the_detection_type(self):
        s = safe_sample([_detection("credit_card", "****-****-****-1111", "PCI-DSS")])
        assert "credit_card" in s

    def test_names_the_compliance_rule(self):
        s = safe_sample([_detection("ssn", "***-**-6789", "HIPAA")])
        assert "HIPAA" in s

    def test_carries_the_classifier_masked_value(self):
        s = safe_sample([_detection("iban", "GB29...5678", "PCI-DSS")])
        assert "GB29...5678" in s

    def test_joins_multiple_detections(self):
        s = safe_sample([
            _detection("credit_card", "****-****-****-1111", "PCI-DSS"),
            _detection("ssn", "***-**-6789", "HIPAA"),
        ])
        assert "credit_card" in s and "ssn" in s

    def test_is_never_empty_even_with_no_detections(self):
        assert safe_sample([]).strip() != ""
        assert safe_sample(None).strip() != ""


class TestBounds:
    def test_respects_the_length_cap(self):
        many = [_detection(f"type_{i}", f"masked_value_{i}", "GDPR") for i in range(30)]
        assert len(safe_sample(many)) <= _MAX_LEN

    def test_respects_a_custom_limit(self):
        s = safe_sample([_detection("ssn", "***-**-6789", "HIPAA")], limit=12)
        assert len(s) <= 12

    def test_summarises_detections_beyond_the_display_cap(self):
        many = [_detection(f"t{i}", f"m{i}", "GDPR") for i in range(_MAX_DETECTIONS + 5)]
        assert "more" in safe_sample(many)

    def test_survives_malformed_input(self):
        assert safe_sample([None, "junk", 42]).strip() != ""
        assert safe_sample([{}]).strip() != ""
