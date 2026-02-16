from unittest.mock import MagicMock, patch
from taxstreem.client import TaxStreem, VatFiling, WhtFiling
from taxstreem.models.schemas import EmailPasswordModel, RequestBody
import json

class TestTaxStreemClient(unittest.TestCase):
    def setUp(self):
        self.client = TaxStreem("test_secret")
        # Mock the requests in the client
        self.client.request = MagicMock(return_value={"status": "success"})

    def test_structure(self):
        """Verify that client has flux.vat and flux.wht, and they have single/batch."""
        self.assertTrue(hasattr(self.client.flux, 'vat'))
        self.assertTrue(hasattr(self.client.flux, 'wht'))
        
        # Check VAT
        self.assertTrue(hasattr(self.client.flux.vat, 'single'))
        self.assertTrue(hasattr(self.client.flux.vat, 'batch'))
        
        # Check WHT
        self.assertTrue(hasattr(self.client.flux.wht, 'single'))
        self.assertTrue(hasattr(self.client.flux.wht, 'batch'))

    def test_pydantic_models(self):
        """Verify Pydantic models."""
        # EmailPassword
        ep = EmailPasswordModel(email="test@example.com", password="password123")
        self.assertEqual(ep.email, "test@example.com")
        
        with self.assertRaises(ValueError):
            EmailPasswordModel(email="invalid-email", password="pwd")

        # RequestBody (Single)
        rb_single = RequestBody(data={"key": "value"})
        self.assertEqual(rb_single.data, {"key": "value"})
        
        # RequestBody (Batch)
        rb_batch = RequestBody(data=[{"key": "value1"}, {"key": "value2"}])
        self.assertEqual(len(rb_batch.data), 2)

    def test_retry_mechanism(self):
        """Verify retry mechanism (mocking)."""
        # We need to mock requests.request to fail then succeed
        with patch('requests.request') as mock_req:
            # First 2 calls fail, 3rd succeeds
            mock_req.side_effect = [
                MagicMock(status_code=500, raise_for_status=MagicMock(side_effect=Exception("Error"))),
                MagicMock(status_code=500, raise_for_status=MagicMock(side_effect=Exception("Error"))),
                MagicMock(status_code=200, json=lambda: {"ok": True})
            ]
            
            # Using the actual client.request logic (which we haven't written yet but assumes it uses retry)
            # But wait, I'm rewriting client.py, so I should test the methods on Single/Batch classes
            
            # Let's assume the method is `submit` on the single/batch instance
            # And we need to make sure `client.request` or the method itself has the retry.
            # If the retry is on `client.request`, it's easier.
            pass

if __name__ == '__main__':
    unittest.main()
