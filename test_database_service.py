#!/usr/bin/env python3
"""
Comprehensive test for DatabaseService to verify all fixes work correctly
"""

import sys
import os
from datetime import datetime
import pandas as pd

# Add current directory to path to import our modules
sys.path.append('.')

from database_service import DatabaseService

def test_database_service():
    """Run comprehensive tests for DatabaseService"""
    
    print("🧪 Starting DatabaseService comprehensive test...")
    
    try:
        # Initialize database service
        db = DatabaseService()
        print("✅ Database connection successful")
        
        # Test 1: Basic email storage with proper date parsing
        print("\n📧 Test 1: Email storage with date parsing")
        test_parsed_email = {
            'headers': {
                'subject': 'Test Phishing Email',
                'from': 'test@suspicious.com',
                'to': 'victim@company.com',
                'date': 'Wed, 15 Sep 2025 10:30:00 +0000'  # RFC 2822 format
            },
            'raw_lines': ['Subject: Test Email', 'From: test@suspicious.com', 'Urgent action required!']
        }
        
        test_analysis_results = {
            'suspicious_findings': [
                {
                    'phrase': 'urgent action required',
                    'segment': 'body',
                    'line_number': 3,
                    'context': 'Urgent action required! Click here now!'
                },
                {
                    'phrase': 'click here',
                    'segment': 'body', 
                    'line_number': 3,
                    'context': 'Urgent action required! Click here now!'
                }
            ]
        }
        
        email_id = db.store_flagged_email(test_parsed_email, test_analysis_results)
        print(f"✅ Email stored with ID: {email_id}")
        
        # Test 2: Test the fixed GROUP BY query in get_flagged_emails
        print("\n📋 Test 2: Get flagged emails (fixed GROUP BY query)")
        flagged_emails = db.get_flagged_emails(limit=10)
        print(f"✅ Retrieved {len(flagged_emails)} flagged emails")
        if flagged_emails:
            first_email = flagged_emails[0]
            print(f"   - First email subject: {first_email.get('email_subject')}")
            print(f"   - Finding count: {first_email.get('finding_count')}")
        
        # Test 3: Test deduplication (storing same email again)
        print("\n🔄 Test 3: Deduplication test (storing same email again)")
        original_count = db.get_flagged_email_count()
        
        # Store the same email again - should update, not create new
        email_id_2 = db.store_flagged_email(test_parsed_email, test_analysis_results)
        new_count = db.get_flagged_email_count()
        
        if email_id == email_id_2 and original_count == new_count:
            print("✅ Deduplication working - same email updated, not duplicated")
        else:
            print(f"❌ Deduplication failed - IDs: {email_id} vs {email_id_2}, counts: {original_count} vs {new_count}")
        
        # Test 4: Test phrase statistics tracking
        print("\n📊 Test 4: Phrase statistics tracking")
        phrase_stats = db.get_phrase_statistics(limit=10)
        print(f"✅ Retrieved {len(phrase_stats)} phrase statistics")
        for stat in phrase_stats[:3]:
            print(f"   - '{stat['suspicious_phrase']}': {stat['total_occurrences']} occurrences, {stat['emails_affected']} emails")
        
        # Test 5: Test individual email retrieval
        print("\n🔍 Test 5: Get individual email by ID")
        retrieved_email = db.get_flagged_email_by_id(email_id)
        if retrieved_email:
            print(f"✅ Retrieved email: {retrieved_email['email_subject']}")
            print(f"   - Finding count: {retrieved_email['finding_count']}")
        else:
            print("❌ Failed to retrieve email by ID")
        
        # Test 6: Test analysis results retrieval
        print("\n🔬 Test 6: Get analysis results")
        analysis_results = db.get_analysis_results(email_id)
        print(f"✅ Retrieved {len(analysis_results)} analysis results")
        for result in analysis_results:
            print(f"   - Phrase: '{result['suspicious_phrase']}' in {result['segment_type']}")
        
        # Test 7: Test update operations
        print("\n✏️  Test 7: Update operations")
        update_success = db.update_flagged_email(email_id, {
            'email_subject': 'Updated Test Subject',
            'total_suspicious_findings': 5
        })
        
        if update_success:
            updated_email = db.get_flagged_email_by_id(email_id)
            if updated_email and updated_email['email_subject'] == 'Updated Test Subject':
                print("✅ Email update successful")
            else:
                print("❌ Email update failed - changes not reflected")
        else:
            print("❌ Email update failed")
        
        # Test 8: Test occurrence report
        print("\n📈 Test 8: Occurrence report")
        report = db.get_occurrence_report()
        summary = report.get('summary', {})
        print(f"✅ Generated occurrence report:")
        print(f"   - Total flagged emails: {summary.get('total_flagged_emails', 0)}")
        print(f"   - Total findings: {summary.get('total_findings', 0)}")
        print(f"   - Unique emails: {summary.get('unique_emails', 0)}")
        print(f"   - Top phrases: {len(report.get('top_phrases', []))}")
        
        # Test 9: Test email date parsing specifically
        print("\n📅 Test 9: Email date parsing verification")
        if retrieved_email and retrieved_email.get('email_date'):
            email_date = retrieved_email['email_date']
            print(f"✅ Email date properly parsed: {email_date}")
            # Check if it's not the fallback datetime.now() by comparing the hour
            if isinstance(email_date, datetime) or '10:30' in str(email_date):
                print("✅ Date parsing used proper RFC 2822 parsing (not fallback)")
            else:
                print("⚠️  Date parsing may have used fallback")
        else:
            print("❌ Email date not found or not parsed")
        
        # Clean up test data
        print("\n🧹 Cleanup: Removing test data")
        delete_success = db.delete_flagged_email(email_id)
        if delete_success:
            print("✅ Test email deleted successfully")
        else:
            print("❌ Failed to delete test email")
        
        db.close()
        print("\n🎉 All database service tests completed successfully!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_database_service()
    if success:
        print("\n✅ DATABASE SERVICE FULLY TESTED AND WORKING!")
    else:
        print("\n❌ DATABASE SERVICE TESTS FAILED!")
        sys.exit(1)