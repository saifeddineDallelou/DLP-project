from unittest.mock import patch, MagicMock
import requests

from api_client import DLPApiClient, _request


def _mock_response(json_body=None, status_code=200, raise_for_status_exc=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    if raise_for_status_exc:
        resp.raise_for_status.side_effect = raise_for_status_exc
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestRequestRetries:
    @patch("api_client.time.sleep", return_value=None)
    @patch("api_client._session.request")
    def test_succeeds_on_first_try(self, mock_req, _sleep):
        mock_req.return_value = _mock_response({"ok": True})
        result = _request("GET", "http://x/y")
        assert result == {"ok": True}
        assert mock_req.call_count == 1

    @patch("api_client.time.sleep", return_value=None)
    @patch("api_client._session.request")
    def test_retries_on_connection_error_then_succeeds(self, mock_req, _sleep):
        mock_req.side_effect = [
            requests.exceptions.ConnectionError("down"),
            _mock_response({"ok": True}),
        ]
        result = _request("GET", "http://x/y")
        assert result == {"ok": True}
        assert mock_req.call_count == 2

    @patch("api_client.time.sleep", return_value=None)
    @patch("api_client._session.request")
    def test_gives_up_after_max_retries(self, mock_req, _sleep):
        mock_req.side_effect = requests.exceptions.Timeout("slow")
        result = _request("GET", "http://x/y")
        assert result is None
        assert mock_req.call_count == 3  # _MAX_RETRIES

    @patch("api_client.time.sleep", return_value=None)
    @patch("api_client._session.request")
    def test_http_error_is_not_retried(self, mock_req, _sleep):
        http_err = requests.exceptions.HTTPError(response=MagicMock(status_code=500, text="boom"))
        mock_req.return_value = _mock_response(raise_for_status_exc=http_err)
        result = _request("GET", "http://x/y")
        assert result is None
        assert mock_req.call_count == 1


class TestDLPApiClient:
    def test_agent_headers_present_when_token_set(self):
        client = DLPApiClient("http://backend", "http://classifier", agent_token="tok123")
        assert client._agent_headers == {"x-agent-token": "tok123"}

    def test_agent_headers_empty_when_no_token(self):
        client = DLPApiClient("http://backend", "http://classifier")
        assert client._agent_headers == {}

    def test_strips_trailing_slashes(self):
        client = DLPApiClient("http://backend/", "http://classifier/")
        assert client.backend_url == "http://backend"
        assert client.classifier_url == "http://classifier"

    @patch("api_client._request")
    def test_enroll_calls_correct_endpoint(self, mock_request):
        mock_request.return_value = {"id": "a1", "token": "t1"}
        client = DLPApiClient("http://backend", "http://classifier")
        result = client.enroll("host1", "Windows 11")

        assert result == {"id": "a1", "token": "t1"}
        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1] == "http://backend/api/agents/enroll"
        assert kwargs["json"] == {"hostname": "host1", "os": "Windows 11", "version": "1.0.0"}

    @patch("api_client._request")
    def test_classify_returns_none_without_text_or_file(self, mock_request):
        client = DLPApiClient("http://backend", "http://classifier")
        result = client.classify()
        assert result is None
        mock_request.assert_not_called()

    @patch("api_client._request")
    def test_classify_sends_text_payload(self, mock_request):
        mock_request.return_value = {"risk_score": 0.1}
        client = DLPApiClient("http://backend", "http://classifier")
        client.classify(text="hello")

        args, kwargs = mock_request.call_args
        assert kwargs["json"] == {"text": "hello"}

    @patch("api_client._request")
    def test_report_ai_leak_attempt_includes_agent_token_header(self, mock_request):
        client = DLPApiClient("http://backend", "http://classifier", agent_token="tok")
        client.report_ai_leak_attempt(
            agent_id="a1", platform="ANTHROPIC_CLAUDE", method="CLIPBOARD",
            content_sample="x", risk_score=0.9,
        )
        args, kwargs = mock_request.call_args
        assert args[1] == "http://backend/api/ai-policy/attempt"
        assert kwargs["headers"] == {"x-agent-token": "tok"}
        assert kwargs["json"]["blocked"] is True

    @patch("api_client._request")
    def test_heartbeat_uses_patch_method(self, mock_request):
        client = DLPApiClient("http://backend", "http://classifier", agent_token="tok")
        client.heartbeat("a1")
        args, _ = mock_request.call_args
        assert args[0] == "PATCH"
        assert args[1] == "http://backend/api/agents/a1/heartbeat"

    @patch("api_client._request")
    def test_list_policies_uses_get_method(self, mock_request):
        mock_request.return_value = [{"id": "p1", "name": "PII"}]
        client = DLPApiClient("http://backend", "http://classifier", agent_token="tok")
        result = client.list_policies()

        args, kwargs = mock_request.call_args
        assert args[0] == "GET"
        assert args[1] == "http://backend/api/policies"
        assert kwargs["headers"] == {"x-agent-token": "tok"}
        assert result == [{"id": "p1", "name": "PII"}]
