import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auth_state
import login_quick
import workbuddy_auth as auth
import workbuddy_checkin as wb


def credential():
    return {'auth': {'accessToken': 'fake-access-token', 'refreshToken': 'fake-refresh-token',
                     'expiresAt': int(time.time()) + 30 * 86400, 'domain': 'www.workbuddy.cn'},
            'account': {'uid': 'test-uid', 'nickname': '13812345678', 'phoneNumber': '13812345678'},
            'disabled': False}


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'workbuddy-auth.json'
        self.data = auth.normalize_auth(credential())

    def test_plain_nested_and_flat_are_minimal(self):
        self.assertEqual(self.data['account'], {'uid': 'test-uid', 'enterpriseId': ''})
        flat = dict(credential()['auth'], **credential()['account'])
        self.assertEqual(self.data, auth.normalize_auth(flat))

    def test_bom_and_unicode_metadata(self):
        raw = credential()
        raw['account']['nickname'] = '测试名字'
        self.path.write_text(json.dumps(raw), encoding='utf-8-sig')
        self.assertNotIn('nickname', auth.read_auth(self.path)['account'])

    def test_millisecond_expiry(self):
        self.assertEqual(auth.epoch_seconds(1792433236267), 1792433236)
        self.assertTrue(wb.is_token_expired({'auth': {'expiresAt': 1000000000000}}))

    def test_bad_expiry_is_fixed_error(self):
        for value in ('secret-value', float('nan'), float('inf'), -1, True):
            with self.subTest(value=type(value).__name__), self.assertRaises(auth.AuthError):
                auth.epoch_seconds(value)

    def test_malformed_token_never_enters_headers(self):
        for value in ({'surprise': 'secret'}, 'fake\r\nAuthorization: fake', ['secret'], None):
            with self.subTest(value=type(value).__name__), self.assertRaises(auth.AuthError):
                wb.billing_headers({'auth': {'accessToken': value}})

    def test_encrypted_fields_resolved_but_metadata_ignored(self):
        raw = credential()
        value = {'$wbEncrypted': 1, 'envelope': 'synthetic-only'}
        raw['auth']['accessToken'] = value
        raw['auth']['refreshToken'] = value
        raw['account']['nickname'] = value
        with patch.object(auth, 'runtime_path', return_value='fake.exe'), patch.object(auth.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, b'{"ok":true,"accessToken":"decrypted-fake"}', b'')
            result = auth.normalize_auth(raw)
        self.assertEqual(result['auth']['refreshToken'], 'decrypted-fake')
        self.assertEqual(run.call_count, 2)
        self.assertNotIn('nickname', result['account'])
        self.assertNotIn('synthetic-only', str(run.call_args.args[0]))
        self.assertIn('synthetic-only', run.call_args.kwargs['input'].decode())

    def test_missing_runtime_has_actionable_safe_error(self):
        with patch.object(auth, 'runtime_path', side_effect=auth.AuthError('需要本机客户端')):
            with self.assertRaisesRegex(auth.AuthError, '需要本机客户端'):
                auth.token_value({'$wbEncrypted': 1, 'envelope': 'synthetic-only'})

    def test_cloud_rejects_envelopes_before_runtime(self):
        raw = credential()
        raw['auth']['refreshToken'] = {'$wbEncrypted': 1, 'envelope': 'synthetic-only'}
        with patch.dict(os.environ, WORKBUDDY_AUTH=json.dumps(raw)), patch.object(sys, 'argv', ['auth_state', 'prepare', str(self.path)]), patch.object(auth, 'runtime_path') as runtime, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(auth_state.main(), 1)
        runtime.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_atomic_write_mode_and_reload(self):
        auth.write_auth(self.path, self.data)
        self.assertEqual(auth.read_auth(self.path), self.data)
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])
        if os.name != 'nt':
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_refresh_rotation_is_used_on_next_process(self):
        with patch.object(wb, 'http_post_json', return_value=({'accessToken': 'new-fake-access', 'refreshToken': 'new-fake-refresh', 'expiresIn': 3600}, 200, None)):
            self.assertTrue(wb.refresh_token(self.path, self.data)[0])
        reloaded = wb.load_auth(self.path)
        self.assertEqual(reloaded['auth']['refreshToken'], 'new-fake-refresh')
        with patch.object(wb, 'http_post_json', return_value=({'accessToken': 'third-fake-access'}, 200, None)) as request:
            wb.refresh_token(self.path, reloaded)
        self.assertEqual(request.call_args.kwargs['headers']['X-Refresh-Token'], 'new-fake-refresh')
        self.assertEqual(reloaded['auth']['expiresAt'], 0)

    def test_github_sync_immediately_after_rotation(self):
        with patch.dict(os.environ, WORKBUDDY_PERSIST_GITHUB='1'), patch.object(auth, 'sync_github') as sync, patch.object(wb, 'http_post_json', return_value=({'accessToken': 'new-fake-access', 'refreshToken': 'new-fake-refresh'}, 200, None)):
            wb.refresh_token(self.path, self.data)
        sync.assert_called_once_with(self.path)
        self.assertEqual(json.loads(self.path.read_text())['auth']['refreshToken'], 'new-fake-refresh')

    def test_persistence_failure_preserves_new_local_credentials(self):
        with patch.dict(os.environ, WORKBUDDY_PERSIST_GITHUB='1'), patch.object(auth, 'sync_github', side_effect=auth.AuthError('sync failed')), patch.object(wb, 'http_post_json', return_value=({'accessToken': 'new-fake-access'}, 200, None)):
            with self.assertRaises(auth.AuthError):
                wb.refresh_token(self.path, self.data)
        self.assertEqual(wb.load_auth(self.path)['auth']['accessToken'], 'new-fake-access')

    def test_session_dead_on_http_200_and_401(self):
        for status in (200, 401):
            data = copy.deepcopy(self.data)
            with patch.object(wb, 'http_post_json', return_value=(None, status, 'code=12153')):
                self.assertFalse(wb.refresh_token(self.path, data)[0])
            self.assertTrue(wb.load_auth(self.path)['disabled'])

    def test_dead_proactive_refresh_does_not_call_checkin(self):
        self.data['auth']['expiresAt'] = 1
        with patch.object(wb, 'http_post_json', return_value=(None, 401, 'code=12153')) as request:
            result = wb.checkin_one_account(self.path, self.data)
        self.assertFalse(result['success'])
        self.assertEqual(request.call_count, 1)

    def test_invalid_and_disabled_accounts_fail_the_command(self):
        self.path.write_text('{"accessToken": ["secret"]}')
        args = type('Args', (), {'auth_dir': self.tmp.name})()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            wb.cmd_signin(args)
        self.data['disabled'] = True
        auth.write_auth(self.path, self.data)
        with patch.object(wb, 'http_post_json') as request, contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            wb.cmd_signin(args)
        request.assert_not_called()

    def test_github_secret_is_piped_and_retried_without_output(self):
        auth.write_auth(self.path, self.data)
        with patch.dict(os.environ, GH_TOKEN='fake-gh-token', GITHUB_REPOSITORY='owner/repo'), patch.object(auth.subprocess, 'run') as run, patch.object(auth.time, 'sleep'):
            run.side_effect = [subprocess.CompletedProcess([], 1, b'sensitive', b'sensitive'), subprocess.CompletedProcess([], 0, b'', b'')]
            auth.sync_github(self.path)
        self.assertEqual(run.call_count, 2)
        self.assertNotIn('fake-access-token', str(run.call_args.args))
        self.assertIn('stdin', run.call_args.kwargs)

    def test_missing_secret_write_token_fails_before_subprocess(self):
        with patch.dict(os.environ, {'GH_TOKEN': ''}), patch.object(auth.subprocess, 'run') as run, self.assertRaises(auth.AuthError):
            auth.sync_github(self.path)
        run.assert_not_called()

    def test_stale_queued_github_snapshot_is_rejected(self):
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123'), patch.object(auth.subprocess, 'run') as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, b'{"updated_at":"2026-10-22T02:00:00Z"}'), subprocess.CompletedProcess([], 0, b'{"created_at":"2026-10-22T01:00:00Z"}')]
            with self.assertRaisesRegex(auth.AuthError, 'Secret'):
                auth.github_preflight()

    def test_redaction_handles_tokens_phone_and_uid(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            wb.print('fake-access-token fake-refresh-token test-uid 13812345678')
        for value in ('fake-access-token', 'fake-refresh-token', 'test-uid', '13812345678'):
            self.assertNotIn(value, output.getvalue())

    def test_legacy_windows_output_encoding_does_not_crash(self):
        output = io.BytesIO()
        stream = io.TextIOWrapper(output, encoding='cp1252', write_through=True)
        wb.print('签到状态 fake-access-token', file=stream)
        self.assertNotIn(b'fake-access-token', output.getvalue())
        stream.detach()

    def test_http_error_body_never_leaks(self):
        import urllib.error
        error = urllib.error.HTTPError('https://example.test', 401, 'no', {}, io.BytesIO(b'fake-refresh-token 13812345678'))
        with patch.object(wb.urllib.request, 'urlopen', side_effect=error):
            self.assertEqual(wb.http_post_json('https://example.test')[2], 'HTTP 401')

    def test_bark_body_is_redacted_before_network(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
        with patch.object(wb, 'BARK_URL', 'https://example.test/fake-key'), patch.object(wb.urllib.request, 'urlopen', return_value=Response()) as send, contextlib.redirect_stdout(io.StringIO()):
            wb.send_bark_notification(0, 0, 1, 0, 0, [{'error': 'fake-access-token 13812345678', 'region': 'cn'}])
        payload = send.call_args.args[0].data.decode()
        self.assertNotIn('fake-access-token', payload)
        self.assertNotIn('13812345678', payload)

    def test_checkin_401_refreshes_once_then_uses_new_access_token(self):
        auth.write_auth(self.path, self.data)
        responses = [(None, 401, 'HTTP 401'),
                     ({'accessToken': 'new-fake-access', 'refreshToken': 'new-fake-refresh'}, 200, None),
                     ({'active': True, 'todayCheckedIn': True}, 200, None)]
        with patch.object(wb, 'http_post_json', side_effect=responses) as request, contextlib.redirect_stdout(io.StringIO()):
            result = wb.checkin_one_account(self.path, self.data)
        self.assertTrue(result['success'])
        self.assertEqual(request.call_count, 3)
        self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer new-fake-access')

    def test_credit_disabled_is_a_failure_without_network(self):
        self.data['disabled'] = True
        auth.write_auth(self.path, self.data)
        with patch.object(wb, 'http_post_json') as request, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wb.print_credit_report(None, self.tmp.name), 1)
        request.assert_not_called()

    def test_current_github_snapshot_passes(self):
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123'), patch.object(auth.subprocess, 'run') as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, b'{"updated_at":"2026-10-21T02:00:00Z"}'), subprocess.CompletedProcess([], 0, b'{"created_at":"2026-10-22T01:00:00Z"}')]
            auth.github_preflight()

    def test_directory_lock_rejects_another_process(self):
        script = 'from workbuddy_auth import auth_lock,AuthError; import sys\ntry:\n with auth_lock(sys.argv[1]): pass\nexcept AuthError: sys.exit(7)\n'
        with auth.auth_lock(self.tmp.name):
            result = subprocess.run([sys.executable, '-c', script, self.tmp.name], cwd=Path(auth.__file__).parent, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_login_preserves_other_accounts_and_does_not_print_token(self):
        other = self.path.parent / 'workbuddy-other.json'
        other.write_text('unchanged')
        responses = [{'code': 0, 'data': {'state': 'fake-state', 'authUrl': 'https://example.test/login'}},
                     {'code': 0, 'data': {'accessToken': 'fresh-fake-token', 'refreshToken': 'fresh-fake-refresh', 'expiresIn': 100}},
                     {'code': 0, 'data': {'uid': 'fake-new-user', 'nickname': '13812345678'}}]
        output = io.StringIO()
        with patch.object(login_quick, 'request', side_effect=responses), contextlib.redirect_stdout(output):
            destination = login_quick.login('cn', self.tmp.name)
        self.assertTrue(destination.exists())
        self.assertEqual(other.read_text(), 'unchanged')
        self.assertNotIn('fresh-fake-token', output.getvalue())
        self.assertNotIn('13812345678', destination.read_text())


@unittest.skipUnless(shutil.which('node'), 'Node required only for synthetic helper tests')
class HelperTests(unittest.TestCase):
    # Synthetic key and token only; this fixture never touches client/user credentials.
    PREFIX = """
const c = require('crypto');
const secret = Buffer.alloc(32, 42).toString('base64');
process._linkedBinding = () => ({loggerGet: () => JSON.stringify({version:1,atRestSecretKey:secret})});
"""

    def fixture(self):
        script = self.PREFIX + """
const k = c.createHash('sha256').update(secret,'utf8').digest();
const keyId = c.createHash('sha256').update(k).digest('hex').slice(0,16);
const lp = s => {const b=Buffer.from(s); const n=Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n,b]);};
const aad=Buffer.concat([Buffer.from('WB-AAD\\0'),Buffer.from([1]),lp('WBEV1'),lp('sym-v1'),Buffer.from([0,0,0,1]),lp(keyId),Buffer.from([2,0,0])]);
const nonce=Buffer.alloc(12,7);
const cipher=c.createCipheriv('aes-256-gcm',k,nonce); cipher.setAAD(aad);
const ciphertext=Buffer.concat([cipher.update('synthetic-fixture-token'),cipher.final()]);
const envelope={suite:1,keyId,nonce:nonce.toString('base64'),authTag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')};
process.stdout.write(JSON.stringify({$wbEncrypted:1,envelope:Buffer.from(JSON.stringify(envelope)).toString('base64')}));
"""
        return json.loads(subprocess.check_output(['node', '-e', script]))

    def run_helper(self, value):
        source = Path(auth.__file__).with_name('workbuddy_decrypt.js').read_text()
        result = subprocess.run(['node', '-e', self.PREFIX + source], input=json.dumps({'version': 1, 'operation': 'decrypt', 'value': value}).encode(), capture_output=True)
        return json.loads(result.stdout)

    def test_authenticated_roundtrip(self):
        self.assertEqual(self.run_helper(self.fixture())['accessToken'], 'synthetic-fixture-token')

    def test_tampered_gcm_tag_is_rejected(self):
        value = self.fixture()
        envelope = json.loads(base64.b64decode(value['envelope']))
        envelope['authTag'] = base64.b64encode(bytes(16)).decode()
        value['envelope'] = base64.b64encode(json.dumps(envelope).encode()).decode()
        result = self.run_helper(value)
        self.assertEqual(result['reason'], 'DECRYPT_FAILED')
        self.assertNotIn('accessToken', result)

    def test_unsupported_suite_and_wrong_key(self):
        for key, value in [('suite', 2), ('keyId', '0000000000000000')]:
            fixture = self.fixture()
            envelope = json.loads(base64.b64decode(fixture['envelope']))
            envelope[key] = value
            fixture['envelope'] = base64.b64encode(json.dumps(envelope).encode()).decode()
            self.assertFalse(self.run_helper(fixture)['ok'])


if __name__ == '__main__':
    unittest.main()
