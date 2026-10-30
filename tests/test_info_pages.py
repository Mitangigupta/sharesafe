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
        self.assertIn('Accidental Exposure of Sensitive Information During', html)
        self.assertIn('Digital File Sharing', html)
        self.assertIn("In today's digital world, people frequently share documents, screenshots and images without realizing that these files may contain sensitive personal information.", html)
        self.assertIn('The core problem is the absence of a simple, user-friendly solution that detects potentially sensitive information and helps individuals protect their privacy before sharing digital files.', html)
        # Verify return link
        self.assertIn('href="/"', html)

    def test_03_proposed_solution_page(self):
        """Proposed Solution page loads successfully with the 4 core actions."""
        res = self.client.get('/proposed-solution')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/proposed-solution" class="nav-page-link active"', html)
        # Verify core proposed solution content
        self.assertIn('ShareSafe is a web-based privacy protection application that allows users to upload documents and images before sharing them with others.', html)
        self.assertIn('Blur', html)
        self.assertIn('Blur sensitive information while retaining the surrounding content.', html)
        self.assertIn('Hide', html)
        self.assertIn('Conceal selected information from view.', html)
        self.assertIn('Remove', html)
        self.assertIn('Permanently redact sensitive information from the file.', html)
        self.assertIn('Keep', html)
        self.assertIn('Retain the information if the user considers it safe to share.', html)
        self.assertIn('After making the necessary changes, users can generate and download a safer version of their original file.', html)
        self.assertIn('ShareSafe aims to make privacy protection a conscious step before every file is shared.', html)

    def test_04_objectives_page(self):
        """Objectives page loads successfully with exactly the three specified objectives."""
        res = self.client.get('/objectives')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/objectives" class="nav-page-link active"', html)
        # Verify Objectives vs Features distinction
        self.assertIn('Do not confuse objectives with features', html)
        # Verify all 3 specified objectives
        self.assertIn('Minimise Accidental Information Exposure', html)
        self.assertIn('To reduce the possibility of unintended disclosure of personal and confidential information during digital file sharing', html)
        self.assertIn('Promote Privacy Awareness and Informed Decision-Making', html)
        self.assertIn("To improve users' understanding of digital privacy by helping them recognise the potential consequences", html)
        self.assertIn('Encourage Context-Aware and Responsible File Sharing', html)
        self.assertIn('To establish a more responsible approach to sharing digital information by ensuring that privacy decisions consider the purpose, recipient and intended audience of a file.', html)

    def test_05_architecture_design_page(self):
        """Architecture Design page loads with verified technologies and Mermaid diagram."""
        res = self.client.get('/architecture-design')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/architecture-design" class="nav-page-link active"', html)
        # Verify architectural sections
        self.assertIn('Frontend', html)
        self.assertIn('Backend', html)
        self.assertIn('APIs and integrations', html)
        self.assertIn('AI Assistance', html)
        self.assertIn('OCR and detection mechanisms', html)
        self.assertIn('File processing and sanitisation', html)
        self.assertIn('Data flow and security architecture', html)
        # Verify Mermaid diagram container
        self.assertIn('class="mermaid"', html)

    def test_06_next_milestones_page(self):
        """Next Milestones page loads with all 5 milestones and long-term vision."""
        res = self.client.get('/next-milestones')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        # Verify active navigation highlight
        self.assertIn('href="/next-milestones" class="nav-page-link active"', html)
        # Verify all 5 milestones
        self.assertIn('Browser Extension Development', html)
        self.assertIn('Integration with Supported Platforms', html)
        self.assertIn('Automated Privacy Screening', html)
        self.assertIn('Improved Context-Aware Recommendations', html)
        self.assertIn('Testing, Optimisation and Expansion', html)
        # Verify Long-Term Vision
        self.assertIn('Long-Term Vision', html)
        self.assertIn('Transform ShareSafe from a standalone web application into an integrated privacy protection tool', html)

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
