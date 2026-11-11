"""Comprehensive Automated Test Suite for Intelligent Vulnerability Management Platform.
Tests pipeline deduplication, state persistence across runs, scoring math,
attack path BFS, RBAC access control, dynamic scanner uploads, and Gemini fallback.
"""
import unittest, os, json, tempfile
import app, db

class TestIVMRPPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use an isolated SQLite database file for testing
        cls.test_db_fd, cls.test_db_path = tempfile.mkstemp(suffix='.db')
        os.environ['IVMRP_DB_PATH'] = cls.test_db_path
        app.app.config['TESTING'] = True
        cls.client = app.app.test_client()

        # Initialize test database and seed with demo data
        db.init_db(cls.test_db_path, seed_if_empty=True)
        app.build()

    @classmethod
    def tearDownClass(cls):
        os.close(cls.test_db_fd)
        if os.path.exists(cls.test_db_path):
            os.remove(cls.test_db_path)

    def _auth_header(self, role):
        return {'Authorization': f'Bearer tok-{role}'}

    def test_01_authentication_and_rbac(self):
        """Test login endpoint and role-based access controls."""
        # 1. Login success
        res = self.client.post('/api/login', json={'username': 'analyst', 'password': 'analyst123'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json.get('token'), 'tok-analyst')

        # 2. Login failure
        res = self.client.post('/api/login', json={'username': 'analyst', 'password': 'wrongpassword'})
        self.assertEqual(res.status_code, 401)

        # 3. Unauthenticated access to protected endpoint
        res = self.client.get('/api/findings')
        self.assertEqual(res.status_code, 401)

        # 4. Role unauthorized (owner cannot run pipeline)
        res = self.client.post('/api/pipeline/run', headers=self._auth_header('owner'))
        self.assertEqual(res.status_code, 403)

        # 5. Role authorized (analyst can run pipeline)
        res = self.client.post('/api/pipeline/run', headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)

    def test_02_pipeline_ingestion_and_deduplication(self):
        """Test that raw records from sources normalize and deduplicate properly."""
        res = self.client.post('/api/pipeline/run', headers=self._auth_header('admin'))
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertEqual(data['sources'], 8)
        self.assertEqual(data['canonical_findings'], 18)
        self.assertEqual(data['duplicates_merged'], 5)
        self.assertEqual(len(data['import_errors']), 1)
        self.assertIn('unknown-host-99', str(data['import_errors']))

    def test_03_risk_scoring_and_urgency(self):
        """Test deterministic risk scoring calculations and urgency thresholds."""
        res = self.client.get('/api/findings', headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)
        findings = res.json

        # Log4Shell on payment-api-prod (internet-facing, crown jewel adjacent, KEV)
        log4shell = next(f for f in findings if f['cve_id'] == 'CVE-2021-44228' and f['asset_name'] == 'payment-api-prod')
        self.assertEqual(log4shell['risk_score'], 100)
        self.assertEqual(log4shell['urgency'], 'EMERGENCY')

        # XZ backdoor on dev-laptop-17 (not internet facing, low criticality)
        xz = next(f for f in findings if f['cve_id'] == 'CVE-2024-3094' and f['asset_name'] == 'dev-laptop-17')
        self.assertEqual(xz['risk_score'], 32)
        self.assertEqual(xz['urgency'], 'LOW')

        # Test explainable factor endpoint
        res_risk = self.client.get(f"/api/findings/{log4shell['finding_id']}/risk", headers=self._auth_header('analyst'))
        self.assertEqual(res_risk.status_code, 200)
        factors = res_risk.json['risk_factors']
        self.assertEqual(len(factors), 8)
        cvss_f = next(x for x in factors if x['factor'] == 'CVSS')
        self.assertEqual(cvss_f['points'], 30.0)

    def test_04_attack_paths_bfs(self):
        """Test BFS traversal finds attack paths from internet-exposed assets to crown jewels."""
        res = self.client.get('/api/attack-paths', headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)
        paths = res.json.get('paths', [])
        self.assertGreaterEqual(len(paths), 3)
        # Verify core-db-prod is targeted
        targets = [p['target'] for p in paths]
        self.assertIn('core-db-prod', targets)

    def test_05_non_destructive_pipeline_and_persistence(self):
        """CRITICAL: Verify that re-running pipeline does NOT wipe task statuses or exceptions!"""
        # 1. Update task TASK-0001 to IN_PROGRESS
        res = self.client.patch('/api/tasks/TASK-0001',
                                json={'status': 'IN_PROGRESS'},
                                headers=self._auth_header('owner'))
        self.assertEqual(res.status_code, 200)

        # 2. Reassign task TASK-0002 to platform-team
        res = self.client.patch('/api/tasks/TASK-0002/reassign',
                                json={'team': 'platform-team'},
                                headers=self._auth_header('manager'))
        self.assertEqual(res.status_code, 200)

        # 3. Request and approve an exception
        res = self.client.post('/api/exceptions',
                               json={'finding_id': 'FND-000003', 'reason': 'Maintenance window required', 'days': 45},
                               headers=self._auth_header('owner'))
        self.assertEqual(res.status_code, 201)
        exc_id = res.json['exception_id']

        res = self.client.post(f'/api/exceptions/{exc_id}/decision',
                               json={'decision': 'APPROVED'},
                               headers=self._auth_header('manager'))
        self.assertEqual(res.status_code, 200)

        # 4. RE-RUN PIPELINE
        res = self.client.post('/api/pipeline/run', headers=self._auth_header('admin'))
        self.assertEqual(res.status_code, 200)

        # 5. Verify TASK-0001 is STILL IN_PROGRESS (not reset to ASSIGNED)
        res = self.client.get('/api/tasks', headers=self._auth_header('analyst'))
        tasks = {t['task_id']: t for t in res.json}
        self.assertEqual(tasks['TASK-0001']['status'], 'IN_PROGRESS')

        # 6. Verify TASK-0002 fix_team is STILL platform-team
        self.assertEqual(tasks['TASK-0002']['fix_team'], 'platform-team')

        # 7. Verify FND-000003 is STILL EXCEPTION_APPROVED
        res = self.client.get('/api/findings', headers=self._auth_header('analyst'))
        findings = {f['finding_id']: f for f in res.json}
        self.assertEqual(findings['FND-000003']['status'], 'EXCEPTION_APPROVED')

    def test_06_dynamic_scanner_upload(self):
        """Test uploading a new scan record via POST /api/sources/upload."""
        scan_payload = [
            {
                "host": "auth-service",
                "cve_id": "CVE-2020-1472",
                "first_seen": "2026-11-11"
            }
        ]
        res = self.client.post('/api/sources/upload', json=scan_payload, headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['status'], 'ok')
        self.assertEqual(res.json['records_ingested'], 1)

    def test_07_ollama_local_model_integration(self):
        """Test Ollama local model detection and response generation when Gemini is unconfigured."""
        res = self.client.get('/api/ai/status', headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json['ollama_configured'])
        self.assertEqual(res.json['active_backend'], 'ollama')
        self.assertIn('deepseek-coder', res.json['model'])

        # Ask question handled by Ollama
        res = self.client.post('/api/ask', json={'question': 'what is log4shell?'}, headers=self._auth_header('analyst'))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['source'], 'ollama')
        self.assertIn('deepseek-coder', res.json['model'])
        self.assertTrue(len(res.json['answer']) > 10)

    def test_08_rule_based_fallback_when_both_unavailable(self):
        """Test graceful rule-based fallback when neither Gemini nor Ollama is available."""
        old_host = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
        try:
            # Simulate Ollama offline
            os.environ['OLLAMA_HOST'] = 'http://localhost:9999'

            # Status endpoint
            res = self.client.get('/api/ai/status', headers=self._auth_header('analyst'))
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json['active_backend'], 'rules')

            # Q&A fallback
            res = self.client.post('/api/ask', json={'question': 'what must the frontend team fix?'}, headers=self._auth_header('analyst'))
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json['source'], 'rules')
            self.assertIn('frontend-team must fix', res.json['answer'])

            # Executive summary fallback
            res = self.client.post('/api/ai/executive-summary', headers=self._auth_header('executive'))
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json['source'], 'rules')
            self.assertIn('findings across', res.json['answer'])
        finally:
            os.environ['OLLAMA_HOST'] = old_host

    def test_09_api_smoke_test_all_endpoints(self):
        """Smoke test all remaining endpoints for 200 responses."""
        auth = self._auth_header('admin')
        self.assertEqual(self.client.get('/api/sources', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/teams', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/assets', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/sla/overdue', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/tickets', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/exceptions', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/analytics', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/audit', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/config', headers=auth).status_code, 200)
        self.assertEqual(self.client.get('/api/findings/FND-000001/detail', headers=auth).status_code, 200)

if __name__ == '__main__':
    unittest.main()
