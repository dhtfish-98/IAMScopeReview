import json
import unittest
from review import review_text


class IAMTests(unittest.TestCase):
    def test_broad_allow_is_reviewed(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Principal": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}
        self.assertEqual({item["rule"] for item in review_text(json.dumps(policy))}, {"broad-action", "broad-resource", "public-principal"})

    def test_deny_and_scoped_allow_are_quiet(self):
        policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}, {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::owned-bucket/*"}]}
        self.assertEqual(review_text(json.dumps(policy)), [])

    def test_not_action_and_invalid_schema(self):
        self.assertEqual(review_text('{"Statement":{"Effect":"Allow","NotAction":"iam:*"}}')[0]["rule"], "allow-not-action")
        for value in ("{}", '{"Statement":3}', '{"Statement":{"Effect":3}}', "not-json"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review_text(value)
