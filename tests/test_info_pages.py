import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

class TestInfoPages(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_01_all_five_nav_links_present_on_home(self):
        """Home page includes all 5 clickable navigation links in the navigation bar."""
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn('/problem-statement', html)
        self.assertIn('Problem Statement', html)
        self.assertIn('/proposed-solution', html)
        self.assertIn('Proposed Solution', html)
        self.assertIn('/objectives', html)
        self.assertIn('Objectives', html)
        self.assertIn('/architecture-design', html)
        self.assertIn('Architecture Design', html)
        self.assertIn('/next-milestones', html)
        self.assertIn('Next Milestones', html)

    def test_02_problem_statement_page(self):
        """Problem Statement page loads successfully with active nav highlight and content."""
        res = self.client.get('/problem-statement')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/problem-statement" class="nav-page-link active"', html)
        # Verify core problem statement content
        self.assertIn('The Silent Threat of', html)
        self.assertIn('Government Identification Records', html)
        self.assertIn('Financial &amp; Payment Credentials', html)
        self.assertIn('Pseudo-Redaction', html)
        self.assertIn('DPDP', html)
        # Verify return link
        self.assertIn('href="/"', html)

    def test_03_proposed_solution_page(self):
        """Proposed Solution page loads successfully with Document Privacy and AI Assistant."""
        res = self.client.get('/proposed-solution')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/proposed-solution" class="nav-page-link active"', html)
        # Verify Part A & Part B
        self.assertIn('Document Privacy Protection Pipeline', html)
        self.assertIn('The Intelligent Privacy Assistant', html)
        self.assertIn('Verhoeff Checksum', html)
        self.assertIn('PyMuPDF', html)
        self.assertIn('Before / After Interactive Split Comparison', html)
        self.assertIn('Why Each Item is Sensitive', html)

    def test_04_objectives_page(self):
        """Objectives page loads successfully with exactly 3 SMART objectives."""
        res = self.client.get('/objectives')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/objectives" class="nav-page-link active"', html)
        # Verify Objectives vs Features distinction
        self.assertIn('Distinguishing Project Objectives from System Features', html)
        # Verify all 3 SMART objectives
        self.assertIn('OBJECTIVE 01', html)
        self.assertIn('Improve Sensitive-Information Detection Precision', html)
        self.assertIn('OBJECTIVE 02', html)
        self.assertIn('Guarantee Forensic Sanitization Integrity and Zero Data Leakage', html)
        self.assertIn('OBJECTIVE 03', html)
        self.assertIn('Improve the Reliability, Explainability, and Context-Awareness of AI Guidance', html)
        # Verify SMART breakdown letters
        self.assertIn('<div class="smart-letter">S</div>', html)
        self.assertIn('<div class="smart-letter">M</div>', html)
        self.assertIn('<div class="smart-letter">A</div>', html)
        self.assertIn('<div class="smart-letter">R</div>', html)
        self.assertIn('<div class="smart-letter">T</div>', html)

    def test_05_architecture_design_page(self):
        """Architecture Design page loads with system blueprints, Mermaid diagram, and tech stack."""
        res = self.client.get('/architecture-design')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/architecture-design" class="nav-page-link active"', html)
        # Verify architectural sections
        self.assertIn('System Overview &amp; Topography', html)
        self.assertIn('Frontend and Backend Architecture', html)
        self.assertIn('The Document Processing Pipeline', html)
        self.assertIn('The AI Assistance Architecture (Local Expert Engine)', html)
        self.assertIn('APIs, Integrations &amp; Technology Stack Inventory', html)
        self.assertIn('Security &amp; Privacy Engineering Safeguards', html)
        # Verify Mermaid diagram container
        self.assertIn('class="mermaid"', html)
        self.assertIn('Pillar A: Document Privacy Pipeline', html)
        self.assertIn('Pillar B: Intelligent Privacy Assistant', html)

    def test_06_next_milestones_page(self):
        """Next Milestones page loads with all 6 milestones and roadmap synthesis."""
        res = self.client.get('/next-milestones')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/next-milestones" class="nav-page-link active"', html)
        # Verify all 6 milestones
        self.assertIn('M1', html)
        self.assertIn('Stabilize the Existing Application', html)
        self.assertIn('M2', html)
        self.assertIn('Improve Detection Accuracy &amp; Privacy Sanitization Verification', html)
        self.assertIn('M3', html)
        self.assertIn('Enhance AI Assistance &amp; Suspicious Content Reasoning', html)
        self.assertIn('M4', html)
        self.assertIn('Explore a Sovereign Browser Extension for Pre-Share Protection', html)
        self.assertIn('M5', html)
        self.assertIn('Investigate Messaging-Platform &amp; OS Share-Sheet Integration', html)
        self.assertIn('M6', html)
        self.assertIn('Comprehensive Security Audit, Demonstration &amp; Release', html)

    def test_07_refresh_and_direct_navigation(self):
        """Each information page is directly accessible via URL and refreshes cleanly."""
        pages = [
            '/problem-statement',
            '/proposed-solution',
            '/objectives',
            '/architecture-design',
            '/next-milestones'
        ]
        for url in pages:
            # First direct visit
            r1 = self.client.get(url)
            self.assertEqual(r1.status_code, 200)
            # Second visit (simulating browser refresh)
            r2 = self.client.get(url)
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(len(r1.get_data()), len(r2.get_data()))

    def test_08_active_state_is_mutually_exclusive(self):
        """Active class is only applied to the current route's link."""
        routes_and_slugs = [
            ('/problem-statement', 'problem-statement'),
            ('/proposed-solution', 'proposed-solution'),
            ('/objectives', 'objectives'),
            ('/architecture-design', 'architecture-design'),
            ('/next-milestones', 'next-milestones')
        ]
        for route, slug in routes_and_slugs:
            res = self.client.get(route)
            html = res.get_data(as_text=True)
            self.assertIn(f'href="/{slug}" class="nav-page-link active"', html)
            for other_route, other_slug in routes_and_slugs:
                if other_slug != slug:
                    self.assertNotIn(f'href="/{other_slug}" class="nav-page-link active"', html)
                    self.assertIn(f'href="/{other_slug}" class="nav-page-link "', html)

if __name__ == '__main__':
    unittest.main()
