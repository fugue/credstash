import unittest
from unittest.mock import patch, MagicMock
from credstash import get_session, reset_sessions

class TestGetSession(unittest.TestCase):
    def setUp(self):
        reset_sessions()

    @patch('boto3.Session')
    def test_get_session_initial_session(self, mock_session):
        mock_session.return_value = 'session1'
        get_session(
            aws_access_key_id='session1'
        )
        mock_session.assert_called_once_with(
            aws_access_key_id='session1',
            aws_secret_access_key=None,
            aws_session_token=None,
            profile_name=None
        )

    @patch('boto3.Session')
    def test_get_session_single_last_session(self, mock_session):
        mock_session.return_value = 'session1'
        get_session(
            aws_access_key_id='session1'
        )
        mock_session.assert_called_once_with(
            aws_access_key_id='session1',
            aws_secret_access_key=None,
            aws_session_token=None,
            profile_name=None
        )
        self.assertEqual(get_session(), 'session1')

    @patch('boto3.Session')
    def test_get_session_two_sessions(self, mock_session):
        mock_session.side_effect = ['session1', 'session2']
        get_session(
            aws_access_key_id='session1'
        )
        mock_session.assert_called_with(
            aws_access_key_id='session1',
            aws_secret_access_key=None,
            aws_session_token=None,
            profile_name=None
        )
        get_session(
            aws_access_key_id='session2'
        )
        mock_session.assert_called_with(
            aws_access_key_id='session2',
            aws_secret_access_key=None,
            aws_session_token=None,
            profile_name=None
        )
        self.assertEqual(get_session(), 'session2')
        self.assertEqual(get_session(aws_access_key_id='session1'), 'session1')
        self.assertEqual(get_session(), 'session1')
        self.assertEqual(get_session(aws_access_key_id='session2'), 'session2')
        self.assertEqual(get_session(), 'session2')

    @patch('boto3.Session')
    def test_get_session_no_params(self, mock_session):
        mock_session.return_value = 'defaultsession'
        self.assertEqual(get_session(), 'defaultsession')
        self.assertEqual(get_session(), 'defaultsession')
        mock_session.assert_called_once_with()
