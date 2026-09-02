import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.edm import (
    ReferenceSet,
    build_reference_set,
    delete_reference_set,
    fingerprint,
    load_reference_sets,
    match_text,
    normalise,
    save_reference_set,
)

SALT = b"test-salt"

CUSTOMERS = [
    {"name": "Sarah Okafor", "email": "sarah.okafor@acme.example", "account": "ACC-4472819"},
    {"name": "Dimitri Volkov", "email": "d.volkov@acme.example", "account": "ACC-8813204"},
    {"name": "Amina Cherif", "email": "amina.cherif@acme.example", "account": "ACC-2290517"},
]


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("EDM_STORE_DIR", str(tmp_path))
    monkeypatch.setenv("EDM_SALT", "test-salt-for-suite")
    return tmp_path


class TestNormalise:
    def test_folds_case(self):
        assert normalise("O'BRIEN") == normalise("o'brien")

    def test_folds_typographic_apostrophes(self):
        # A database holds O'Brien; a Word document holds O’Brien.
        assert normalise("O'Brien") == normalise("O’Brien")

    def test_strips_accents(self):
        assert normalise("Amina Chérif") == normalise("Amina Cherif")

    def test_collapses_separators(self):
        # A database export stores an unformatted number; a document writes it
        # with spaces or dashes. Without this, EDM matches almost nothing.
        assert normalise("4111 1111 1111 1111") == normalise("4111-1111-1111-1111")
        assert normalise("4111111111111111") == normalise("4111 1111 1111 1111")

    def test_handles_none_and_empty(self):
        assert normalise(None) == ""
        assert normalise("") == ""


class TestFingerprint:
    def test_is_deterministic(self):
        assert fingerprint("Sarah Okafor", SALT) == fingerprint("Sarah Okafor", SALT)

    def test_differs_per_value(self):
        assert fingerprint("Sarah Okafor", SALT) != fingerprint("Dimitri Volkov", SALT)

    def test_matches_across_formatting(self):
        assert fingerprint("4111 1111 1111 1111", SALT) == fingerprint("4111111111111111", SALT)

    def test_a_different_salt_gives_a_different_digest(self):
        # The salt is what stops a stolen index being dictionary-attacked:
        # a surname or a 6-digit account number has far too little entropy to
        # survive an unsalted hash.
        assert fingerprint("Sarah Okafor", b"salt-a") != fingerprint("Sarah Okafor", b"salt-b")

    def test_never_contains_the_source_value(self):
        digest = fingerprint("Sarah Okafor", SALT)
        assert "sarah" not in digest.lower()
        assert "okafor" not in digest.lower()


class TestBuildReferenceSet:
    def test_indexes_every_column(self):
        rs = build_reference_set("customers", CUSTOMERS, salt=SALT)
        assert set(rs.columns) == {"name", "email", "account"}
        assert rs.total_values == 9

    def test_stores_only_digests(self):
        # The security property the whole module rests on: uploading a
        # customer database to a DLP tool must not create a copy of it.
        rs = build_reference_set("customers", CUSTOMERS, salt=SALT)
        blob = repr(rs)
        for row in CUSTOMERS:
            for value in row.values():
                assert value not in blob

    def test_skips_values_too_short_to_be_distinctive(self):
        # A 3-character token appears constantly in ordinary prose; indexing
        # one guarantees a false positive on every document.
        rs = build_reference_set("tiny", [{"code": "AB", "name": "Xu"}], salt=SALT)
        assert rs.total_values == 0

    def test_deduplicates_repeated_values(self):
        rows = [{"city": "Tunis"}, {"city": "Tunis"}, {"city": "Sfax"}]
        rs = build_reference_set("cities", rows, salt=SALT)
        assert len(rs.columns["city"]) == 2

    def test_ignores_null_values(self):
        rs = build_reference_set("partial", [{"name": "Sarah Okafor", "phone": None}], salt=SALT)
        assert "phone" not in rs.columns

    def test_tolerates_malformed_rows(self):
        rs = build_reference_set("mixed", [None, "junk", {"name": "Sarah Okafor"}], salt=SALT)
        assert rs.total_values == 1


class TestMatchText:
    def _set(self):
        return build_reference_set("customers", CUSTOMERS, rule="INTERNAL", salt=SALT)

    def test_finds_a_customer_name_no_regex_could_describe(self):
        # The capability regex fundamentally cannot provide: "Sarah Okafor"
        # has no distinguishing shape.
        hits = match_text("Please review the file for Sarah Okafor.", [self._set()], salt=SALT)
        assert len(hits) == 1
        assert hits[0]["type"] == "edm:customers:name"

    def test_finds_an_account_reference(self):
        hits = match_text("Ref ACC-4472819 was reconciled.", [self._set()], salt=SALT)
        assert any("account" in h["type"] for h in hits)

    def test_is_silent_on_a_name_not_in_the_reference_set(self):
        # The point of EDM over regex: a made-up example must not fire.
        hits = match_text("Please review the file for John Smith.", [self._set()], salt=SALT)
        assert hits == []

    def test_counts_how_many_values_matched(self):
        text = "Sarah Okafor, Dimitri Volkov and Amina Cherif all appear here."
        hits = match_text(text, [self._set()], salt=SALT)
        name_hit = next(h for h in hits if h["type"].endswith(":name"))
        assert name_hit["_count"] == 3

    def test_a_bigger_match_carries_more_weight(self):
        one = match_text("Sarah Okafor", [self._set()], salt=SALT)
        many = match_text("Sarah Okafor Dimitri Volkov Amina Cherif", [self._set()], salt=SALT)
        assert many[0]["_weight"] > one[0]["_weight"]

    def test_never_reports_the_matched_value(self):
        # A match is by construction a real record from the organisation's
        # own database. Echoing it into an incident would defeat the purpose.
        hits = match_text("Sarah Okafor and ACC-4472819", [self._set()], salt=SALT)
        blob = str(hits)
        assert "Sarah" not in blob
        assert "ACC-4472819" not in blob

    def test_names_the_column_that_matched(self):
        hits = match_text("Sarah Okafor", [self._set()], salt=SALT)
        assert "customers.name" in hits[0]["value"]

    def test_matches_across_formatting_differences(self):
        rs = build_reference_set("cards", [{"pan": "4111111111111111"}], salt=SALT)
        hits = match_text("Card on file: 4111 1111 1111 1111", [rs], salt=SALT)
        assert len(hits) == 1

    def test_carries_the_reference_set_compliance_rule(self):
        rs = build_reference_set("patients", [{"mrn": "MRN-99381"}], rule="HIPAA", salt=SALT)
        hits = match_text("Chart MRN-99381 attached", [rs], salt=SALT)
        assert hits[0]["rule"] == "HIPAA"

    def test_reports_higher_confidence_than_a_shape_match(self):
        # An exact match against a known record is not a guess.
        hits = match_text("Sarah Okafor", [self._set()], salt=SALT)
        assert hits[0]["confidence"] > 0.95

    def test_searches_every_configured_set(self):
        customers = self._set()
        patients = build_reference_set("patients", [{"mrn": "MRN-99381"}], rule="HIPAA", salt=SALT)
        hits = match_text("Sarah Okafor and MRN-99381", [customers, patients], salt=SALT)
        assert {h["type"].split(":")[1] for h in hits} == {"customers", "patients"}

    def test_returns_nothing_without_a_reference_set(self):
        assert match_text("Sarah Okafor", [], salt=SALT) == []

    def test_returns_nothing_for_empty_text(self):
        assert match_text("", [self._set()], salt=SALT) == []


class TestPersistence:
    def test_round_trips_a_reference_set(self, store):
        rs = build_reference_set("customers", CUSTOMERS)
        save_reference_set(rs)

        loaded = load_reference_sets()
        assert len(loaded) == 1
        assert loaded[0].name == "customers"
        assert loaded[0].total_values == rs.total_values

    def test_the_stored_file_contains_no_raw_values(self, store):
        save_reference_set(build_reference_set("customers", CUSTOMERS))
        blob = "\n".join(p.read_text(encoding="utf-8") for p in store.glob("*.json"))
        for row in CUSTOMERS:
            for value in row.values():
                assert value not in blob

    def test_a_loaded_set_still_matches(self, store):
        save_reference_set(build_reference_set("customers", CUSTOMERS))
        hits = match_text("Sarah Okafor was here", load_reference_sets())
        assert len(hits) == 1

    def test_one_corrupt_file_does_not_stop_the_others(self, store):
        save_reference_set(build_reference_set("good", CUSTOMERS))
        (store / "broken.json").write_text("{not json", encoding="utf-8")

        loaded = load_reference_sets()
        assert [rs.name for rs in loaded] == ["good"]

    def test_delete_removes_a_set(self, store):
        save_reference_set(build_reference_set("customers", CUSTOMERS))
        assert delete_reference_set("customers") is True
        assert load_reference_sets() == []

    def test_delete_reports_a_missing_set(self, store):
        assert delete_reference_set("nope") is False

    def test_an_absent_store_is_not_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EDM_STORE_DIR", str(tmp_path / "does-not-exist"))
        assert load_reference_sets() == []


class TestEngineIntegration:
    def test_classification_works_with_no_reference_sets(self, store):
        # EDM is opt-in. The default path must be untouched.
        from src.engine import classify_text
        result = classify_text("Card 4111111111111111", None)
        assert result["risk_score"] > 0
        assert all(not d["type"].startswith("edm:") for d in result["detections"])

    def test_an_edm_hit_raises_the_risk_score(self, store):
        from src.engine import classify_text

        plain = classify_text("Meeting notes about Sarah Okafor", None)
        save_reference_set(build_reference_set("customers", CUSTOMERS))
        with_edm = classify_text("Meeting notes about Sarah Okafor", None)

        assert with_edm["risk_score"] > plain["risk_score"]
        assert any(d["type"].startswith("edm:") for d in with_edm["detections"])

    def test_edm_finds_what_regex_cannot(self, store):
        from src.engine import classify_text

        # A bare customer name: no pattern in the engine describes it.
        text = "Please send the report to Dimitri Volkov."
        assert classify_text(text, None)["risk_score"] == 0.0

        save_reference_set(build_reference_set("customers", CUSTOMERS))
        assert classify_text(text, None)["risk_score"] > 0.0

# A set built to be DELIBERATELY dangerous per-value: `city` and `surname` are
# common enough that indexing them alone guarantees false positives. That is
# the situation correlation exists to make safe.
STAFF = [
    {"surname": "Okafor", "city": "Manchester", "payroll": "PR-99120"},
    {"surname": "Volkov", "city": "Manchester", "payroll": "PR-44317"},
    {"surname": "Cherif", "city": "Lyon", "payroll": "PR-70225"},
]


class TestRowCorrelation:
    def _staff(self, min_fields=2):
        return build_reference_set(
            "staff", STAFF, rule="INTERNAL", salt=SALT, min_fields=min_fields
        )

    def test_one_field_alone_does_not_fire(self):
        # "Manchester" is in the reference set and belongs to two real
        # records -- and on its own it means nothing. Per-value matching
        # would flag this sentence; that is the false positive correlation
        # is for.
        hits = match_text("Our Manchester office is hiring.", [self._staff()], salt=SALT)
        assert hits == []

    def test_two_fields_of_the_same_record_fire(self):
        hits = match_text(
            "Okafor, based in Manchester, filed the report.",
            [self._staff()], salt=SALT,
        )
        assert len(hits) == 1
        assert hits[0]["type"] == "edm:staff:row"
        assert hits[0]["_count"] == 1
        assert hits[0]["_fields"] == ["city", "surname"]

    def test_two_fields_from_DIFFERENT_records_do_not_fire(self):
        # The whole correctness question. "Cherif" is a real surname in the
        # set and "Manchester" is a real city in the set -- but no single
        # employee has both. Crediting them to one record would invent a
        # correlation that does not exist.
        hits = match_text(
            "Cherif visited the Manchester branch.", [self._staff()], salt=SALT
        )
        assert hits == []

    def test_a_full_record_fires_on_all_three_fields(self):
        hits = match_text(
            "Okafor / Manchester / PR-99120", [self._staff(min_fields=2)], salt=SALT
        )
        assert len(hits) == 1
        assert hits[0]["_fields"] == ["city", "payroll", "surname"]

    def test_requiring_three_fields_rejects_a_two_field_leak(self):
        hits = match_text(
            "Okafor, Manchester", [self._staff(min_fields=3)], salt=SALT
        )
        assert hits == []

    def test_requiring_three_fields_accepts_the_full_record(self):
        hits = match_text(
            "Okafor, Manchester, PR-99120", [self._staff(min_fields=3)], salt=SALT
        )
        assert len(hits) == 1
        assert hits[0]["_count"] == 1

    def test_counts_each_matched_record_once(self):
        # Two different employees fully leaked -- two records, reported as one
        # detection carrying a count of 2 because they hit the same columns.
        hits = match_text(
            "Okafor Manchester PR-99120 and Volkov Manchester PR-44317",
            [self._staff()], salt=SALT,
        )
        assert len(hits) == 1
        assert hits[0]["_count"] == 2

    def test_never_reports_the_matched_values(self):
        hits = match_text(
            "Okafor, Manchester, PR-99120", [self._staff()], salt=SALT
        )
        blob = " ".join(str(v) for v in hits[0].values())
        for secret in ("Okafor", "Manchester", "PR-99120"):
            assert secret not in blob

    def test_a_record_match_outweighs_a_single_value_match(self):
        correlated = match_text("Okafor Manchester", [self._staff()], salt=SALT)
        per_value = match_text(
            "Okafor", [build_reference_set("staff", STAFF, salt=SALT)], salt=SALT
        )
        assert correlated[0]["_weight"] > per_value[0]["_weight"]

    def test_min_fields_one_is_unchanged_per_value_behaviour(self):
        rs = self._staff(min_fields=1)
        assert rs.correlated is False
        assert rs.row_index == {}
        hits = match_text("Our Manchester office", [rs], salt=SALT)
        assert len(hits) == 1
        assert hits[0]["type"] == "edm:staff:city"

    def test_the_row_index_holds_no_raw_values(self):
        rs = self._staff()
        blob = repr(rs.row_index)
        for secret in ("Okafor", "Manchester", "PR-99120"):
            assert secret not in blob


class TestCorrelatedPersistence:
    def test_round_trips_and_still_correlates(self, store):
        rs = build_reference_set("staff", STAFF, min_fields=2)
        save_reference_set(rs)
        loaded = load_reference_sets()[0]
        assert loaded.min_fields == 2
        assert loaded.correlated is True
        assert loaded.row_count == 3
        assert loaded.columns.keys() == rs.columns.keys()
        assert match_text("Okafor, Manchester", [loaded]) != []
        assert match_text("Cherif, Manchester", [loaded]) == []

    def test_the_stored_file_contains_no_raw_values(self, store):
        save_reference_set(build_reference_set("staff", STAFF, min_fields=2))
        blob = (store / "staff.json").read_text(encoding="utf-8")
        for secret in ("Okafor", "Manchester", "PR-99120"):
            assert secret not in blob

    def test_a_per_value_set_stores_no_row_linkage(self, store):
        # Opting out of correlation opts out of recording which values belong
        # to the same person -- the file is exactly what it always was.
        import json
        save_reference_set(build_reference_set("staff", STAFF, min_fields=1))
        raw = json.loads((store / "staff.json").read_text(encoding="utf-8"))
        assert "rowIndex" not in raw
        assert "columns" in raw

    def test_a_legacy_file_without_min_fields_loads_as_per_value(self, store):
        # Files written before correlation existed must keep working.
        import json
        (store / "legacy.json").write_text(json.dumps({
            "name": "legacy",
            "rule": "INTERNAL",
            "maxWords": 2,
            "columns": {"name": [fingerprint("Sarah Okafor")]},
        }), encoding="utf-8")
        loaded = [s for s in load_reference_sets() if s.name == "legacy"][0]
        assert loaded.min_fields == 1
        assert loaded.correlated is False
        assert match_text("Sarah Okafor", [loaded]) != []

class TestRowAttribution:
    """
    The subtle correctness point behind _match_rows' docstring.

    Plenty of real values are a surname in one record and a place in another
    -- Lincoln, Preston, Washington. Indexing digest -> rows and then
    crediting every column that digest appears in to every one of those rows
    invents correlations: one token would look like two different fields of
    two different people at once. Attribution has to be per (column, row).
    """

    OVERLAP = [
        {"surname": "Lincoln", "city": "Manchester"},
        {"surname": "Volkov",  "city": "Lincoln"},
    ]

    def _set(self):
        return build_reference_set(
            "overlap", self.OVERLAP, salt=SALT, min_fields=2
        )

    def test_one_ambiguous_token_is_not_two_fields_of_one_record(self):
        # "Lincoln" is row 0's surname AND row 1's city -- one token, two
        # records, one field each. Neither record reaches two fields, so
        # nothing fires. A digest-keyed index that ignored which COLUMN the
        # row matched on would credit both columns to both rows and report
        # two full-record matches from a single word.
        assert match_text("Lincoln", [self._set()], salt=SALT) == []

    def test_the_ambiguous_token_still_fires_with_a_genuine_second_field(self):
        # Same token, but now row 0's own city is present too: that really is
        # two fields of one record.
        hits = match_text("Lincoln, Manchester", [self._set()], salt=SALT)
        assert len(hits) == 1
        assert hits[0]["_count"] == 1
        assert hits[0]["_fields"] == ["city", "surname"]
