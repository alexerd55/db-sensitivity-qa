"""Unit tests for detectors.py — no DB required."""

import pytest
from dbqa.detectors import (
    Tag,
    detect_by_name,
    detect_values,
    luhn_check,
    mask_email,
    mask_generic,
    mask_phone,
)

class TestDetectByName:
    def test_email(self):
        assert Tag.EMAIL in detect_by_name("email")
        assert Tag.EMAIL in detect_by_name("user_email")
        assert Tag.EMAIL in detect_by_name("e_mail")

    def test_phone(self):
        assert Tag.PHONE in detect_by_name("phone")
        assert Tag.PHONE in detect_by_name("mobile")
        assert Tag.PHONE in detect_by_name("tel")

    def test_name(self):
        assert Tag.NAME in detect_by_name("first_name")
        assert Tag.NAME in detect_by_name("last_name")
        assert Tag.NAME in detect_by_name("fullname")

    def test_dob(self):
        assert Tag.DOB in detect_by_name("date_of_birth")
        assert Tag.DOB in detect_by_name("dob")
        assert Tag.DOB in detect_by_name("birth_date")

    def test_gov_id(self):
        assert Tag.GOV_ID in detect_by_name("jmbg")
        assert Tag.GOV_ID in detect_by_name("ssn")
        assert Tag.GOV_ID in detect_by_name("passport_number")

    def test_payment(self):
        assert Tag.PAYMENT in detect_by_name("iban")
        assert Tag.PAYMENT in detect_by_name("card_number")
        assert Tag.PAYMENT in detect_by_name("cc_num")

    def test_auth(self):
        assert Tag.AUTH in detect_by_name("password")
        assert Tag.AUTH in detect_by_name("api_key")
        assert Tag.AUTH in detect_by_name("secret_token")
        assert Tag.AUTH in detect_by_name("pwd")

    def test_no_match(self):
        assert detect_by_name("created_at") == set()
        assert detect_by_name("quantity") == set()
        assert detect_by_name("product_id") == set()

    def test_multi_tag(self):
        tags = detect_by_name("email_token")
        assert Tag.EMAIL in tags
        assert Tag.AUTH in tags


class TestDetectValues:
    def test_email_detection(self):
        values = ["alice@example.com", "bob@test.org", "notanemail", "random"]
        results = {r.tag: r for r in detect_values(values)}
        assert Tag.EMAIL in results
        assert results[Tag.EMAIL].hit_count == 2

    def test_email_masking(self):
        values = ["alice@example.com"]
        results = {r.tag: r for r in detect_values(values)}
        ex = results[Tag.EMAIL].examples_masked[0]
        assert "@" in ex
        assert "alice" not in ex 

    def test_uuid_detection(self):
        values = [
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "not-a-uuid",
        ]
        results = {r.tag: r for r in detect_values(values)}
        assert Tag.UUID in results
        assert results[Tag.UUID].hit_count == 2

    def test_jwt_detection(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        results = {r.tag: r for r in detect_values([jwt, "plain text", "12345"])}
        assert Tag.JWT in results

    def test_hash_detection(self):
        md5    = "d41d8cd98f00b204e9800998ecf8427e"
        sha1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = {r.tag: r for r in detect_values([md5, sha1, sha256])}
        assert Tag.HASH_LIKE in results
        assert results[Tag.HASH_LIKE].hit_count == 3

    def test_no_raw_values_in_evidence(self):
        """Evidence must be masked, never raw."""
        values = ["alice@example.com"]
        results = {r.tag: r for r in detect_values(values)}
        for r in results.values():
            for ex in r.examples_masked:
                assert "alice" not in ex

    def test_empty_values(self):
        assert detect_values([]) == []

    def test_hit_rate(self):
        values = ["alice@example.com"] + ["notanemail"] * 4
        results = {r.tag: r for r in detect_values(values)}
        assert abs(results[Tag.EMAIL].hit_rate - 0.2) < 0.01


class TestLuhnCheck:
    def test_valid_visa(self):
        assert luhn_check("4532015112830366") is True

    def test_valid_mastercard(self):
        assert luhn_check("5425233430109903") is True

    def test_invalid(self):
        assert luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert luhn_check("1234") is False

    def test_non_digits(self):
        assert luhn_check("abcd-efgh") is False


class TestMasking:
    def test_mask_email(self):
        assert mask_email("alice@example.com") == "a***@e***.com"
        assert "alice" not in mask_email("alice@example.com")

    def test_mask_phone_length(self):
        result = mask_phone("+38162123456")
        assert "****" in result
        assert len(result) < len("+38162123456") + 5

    def test_mask_generic_keep_last(self):
        assert mask_generic("IBAN1234567890", keep_last=4) == "****7890"

    def test_mask_generic_short(self):
        assert mask_generic("ab", keep_last=4) == "****"
