import json
import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from review import review_text


class RegressionTests(unittest.TestCase):

    def test_invalid_fields_do_not_return_clean(self):
        for statement in ({"Effect":"Allow","Action":[123],"Resource":"owned"}, {"Effect":"Other","Action":"*"}, {"Effect":"Allow","Action":[]}):
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                review_text(json.dumps({"Statement":statement}))
    def test_complement_scopes(self):
        rules={x["rule"] for x in review_text(json.dumps({"Statement":{"Effect":"Allow","Action":"s3:GetObject","NotResource":"owned","NotPrincipal":{"AWS":"owned"}}}))}
        self.assertEqual(rules,{"allow-not-resource","allow-not-principal"})
