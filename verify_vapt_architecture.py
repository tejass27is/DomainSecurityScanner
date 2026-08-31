#!/usr/bin/env python3
"""
VAPT Multi-Region Architecture Verification Script

This script verifies that all components of the multi-region VAPT system are
correctly implemented and integrated.
"""

import os
import re
import sys
from pathlib import Path

class Verifier:
    def __init__(self):
        self.root = Path(__file__).parent
        self.checks = []
        self.passed = 0
        self.failed = 0

    def add_check(self, name, result, details=""):
        status = "✅ PASS" if result else "❌ FAIL"
        self.checks.append((name, result, details))
        if result:
            self.passed += 1
        else:
            self.failed += 1
        print(f"{status}: {name}")
        if details:
            print(f"      {details}")

    def check_file_exists(self, path, name):
        """Verify a file exists."""
        exists = (self.root / path).exists()
        self.add_check(
            name,
            exists,
            f"Path: {path}" if exists else f"Missing: {path}"
        )
        return exists

    def check_file_contains(self, path, pattern, name, should_not_contain=False):
        """Verify a file contains (or doesn't contain) a pattern."""
        file_path = self.root / path
        if not file_path.exists():
            self.add_check(name, False, f"File not found: {path}")
            return False
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = file_path.read_text(encoding='cp1252', errors='ignore')
        
        matches = re.search(pattern, content, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        
        if should_not_contain:
            result = not matches
            detail = f"Pattern not found (correct)" if result else f"Pattern found (should be removed): {pattern}"
        else:
            result = bool(matches)
            detail = f"Pattern found (correct)" if result else f"Pattern missing: {pattern}"
        
        self.add_check(name, result, detail)
        return result

    def verify_backend_models(self):
        """Verify database models are correctly defined."""
        print("\n--- Backend: Database Models ---")
        
        self.check_file_exists(
            "Scanner-Backend/app/db/models.py",
            "Database models file exists"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/db/models.py",
            r"class Region\(Base\):",
            "Region model defined"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/db/models.py",
            r"class OrganizationRegion\(Base\):",
            "OrganizationRegion model defined"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/db/models.py",
            r"region_id.*ForeignKey.*Region",
            "OrganizationRegion has foreign key to Region"
        )

    def verify_backend_migrations(self):
        """Verify database migration script is set up."""
        print("\n--- Backend: Database Migrations ---")
        
        self.check_file_exists(
            "Scanner-Backend/app/db/init_db.py",
            "Migration script exists"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/db/init_db.py",
            r"INSERT INTO regions",
            "Regions seed data included"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/db/init_db.py",
            r"ACC-IND.*ACC-SA",
            "Default regions (ACC-IND, ACC-SA) seeded"
        )

    def verify_backend_vapt_routes(self):
        """Verify VAPT routes are org-scoped."""
        print("\n--- Backend: VAPT Routes ---")
        
        self.check_file_exists(
            "Scanner-Backend/app/api/vapt/routes.py",
            "VAPT routes file exists"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"def _get_org_region_status",
            "Org-scoped region status function exists"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"@router\.post\(\"/request-access\"\)",
            "Request access endpoint defined"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"@router\.get\(\"/access-status\"\)",
            "Access status endpoint defined"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"@router\.post\(\"/admin/approve-access\"\)",
            "Admin approve endpoint defined"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"approved_regions.*=",
            "Region status arrays returned (approved)"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"pending_regions",
            "Region status arrays returned (pending)"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/api/vapt/routes.py",
            r"available_regions",
            "Region status arrays returned (available)"
        )

    def verify_frontend_profile(self):
        """Verify frontend Profile page is dynamic."""
        print("\n--- Frontend: Profile Page ---")
        
        self.check_file_exists(
            "ShieldStat-Frontend/src/pages/Profile.jsx",
            "Profile page exists"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/Profile.jsx",
            r"vaptAccessStatus\.available_regions",
            "Uses available_regions from API"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/Profile.jsx",
            r"approved_regions.*map",
            "Renders approved regions dynamically"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/Profile.jsx",
            r"pending_regions.*map",
            "Renders pending regions dynamically"
        )
        
        # Check that hardcoded regions are NOT in this file
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/Profile.jsx",
            r"\[\s*['\"]ACC-IND['\"],",
            "No hardcoded region array in Profile",
            should_not_contain=True
        )

    def verify_frontend_vapt_upload(self):
        """Verify VAPT upload page is dynamic."""
        print("\n--- Frontend: VAPT Upload Gate ---")
        
        self.check_file_exists(
            "ShieldStat-Frontend/src/pages/VaptUpload.jsx",
            "VAPT upload page exists"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/VaptUpload.jsx",
            r"available_regions",
            "Uses available_regions from API"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/VaptUpload.jsx",
            r"selectedRequestRegions",
            "Uses dynamic selected regions state"
        )
        
        # Check that hardcoded regions are NOT in this file
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/VaptUpload.jsx",
            r"<option value=['\"]ACC-",
            "No hardcoded region options",
            should_not_contain=True
        )

    def verify_frontend_admin_requests(self):
        """Verify admin request page handles multi-region."""
        print("\n--- Frontend: Admin VAPT Access Requests ---")
        
        self.check_file_exists(
            "ShieldStat-Frontend/src/pages/AdminVaptAccessRequests.jsx",
            "Admin VAPT requests page exists"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/AdminVaptAccessRequests.jsx",
            r"requested_regions.*map",
            "Maps over requested_regions array"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/AdminVaptAccessRequests.jsx",
            r"approved_regions.*map",
            "Maps over approved_regions array"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/pages/AdminVaptAccessRequests.jsx",
            r"org_id",
            "Uses org_id for approval"
        )

    def verify_api_service(self):
        """Verify API service functions."""
        print("\n--- Frontend: API Service ---")
        
        self.check_file_exists(
            "ShieldStat-Frontend/src/services/api.js",
            "API service exists"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/services/api.js",
            r"export function requestVaptAccess",
            "requestVaptAccess function exported"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/services/api.js",
            r"export function getVaptAccessStatus",
            "getVaptAccessStatus function exported"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/services/api.js",
            r"export function getAdminVaptAccessRequests",
            "getAdminVaptAccessRequests function exported"
        )
        
        self.check_file_contains(
            "ShieldStat-Frontend/src/services/api.js",
            r"export function approveVaptAccessRequest",
            "approveVaptAccessRequest function exported"
        )

    def verify_middleware(self):
        """Verify middleware is org-scoped."""
        print("\n--- Backend: Middleware ---")
        
        self.check_file_exists(
            "Scanner-Backend/app/core/middleware.py",
            "Middleware file exists"
        )
        
        self.check_file_contains(
            "Scanner-Backend/app/core/middleware.py",
            r"def require_vapt_access",
            "VAPT access check defined"
        )

    def run_all_checks(self):
        """Run all verification checks."""
        print("=" * 70)
        print("VAPT Multi-Region Architecture Verification")
        print("=" * 70)
        
        self.verify_backend_models()
        self.verify_backend_migrations()
        self.verify_backend_vapt_routes()
        self.verify_frontend_profile()
        self.verify_frontend_vapt_upload()
        self.verify_frontend_admin_requests()
        self.verify_api_service()
        self.verify_middleware()
        
        print("\n" + "=" * 70)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        print("=" * 70)
        
        if self.failed > 0:
            print("\n⚠️  Some checks failed. Review the output above.")
            return False
        else:
            print("\n✅ All checks passed! Multi-region VAPT system is properly implemented.")
            return True

if __name__ == "__main__":
    verifier = Verifier()
    success = verifier.run_all_checks()
    sys.exit(0 if success else 1)
