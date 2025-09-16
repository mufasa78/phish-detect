#!/usr/bin/env python3
"""
Test script to verify data integrity fixes in database_service.py
Tests phrase statistics accuracy across all operations
"""

import os
import sys
from datetime import datetime, timedelta
from database_service import DatabaseService

def setup_test_database():
    """Initialize the database with required tables for testing"""
    db = DatabaseService()
    cursor = db._get_cursor()
    
    try:
        # Create tables if they don't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flagged_emails (
                id SERIAL PRIMARY KEY,
                email_hash VARCHAR(255) UNIQUE NOT NULL,
                email_subject VARCHAR(500),
                email_from VARCHAR(200),
                email_to VARCHAR(200),
                email_date TIMESTAMP,
                total_suspicious_findings INTEGER DEFAULT 0,
                email_content TEXT,
                risk_level VARCHAR(50) DEFAULT 'medium',
                flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id SERIAL PRIMARY KEY,
                flagged_email_id INTEGER REFERENCES flagged_emails(id) ON DELETE CASCADE,
                suspicious_phrase VARCHAR(500) NOT NULL,
                segment_type VARCHAR(100),
                line_number INTEGER,
                context_content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phrase_statistics (
                id SERIAL PRIMARY KEY,
                suspicious_phrase VARCHAR(500) UNIQUE NOT NULL,
                total_occurrences INTEGER DEFAULT 0,
                emails_affected INTEGER DEFAULT 0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Clear existing test data
        cursor.execute("DELETE FROM analysis_results")
        cursor.execute("DELETE FROM flagged_emails") 
        cursor.execute("DELETE FROM phrase_statistics")
        
        print("✅ Test database setup completed")
        
    finally:
        cursor.close()
        db.close()

def get_phrase_stats(db, phrase):
    """Helper to get current phrase statistics"""
    cursor = db._get_cursor()
    try:
        cursor.execute("""
            SELECT total_occurrences, emails_affected 
            FROM phrase_statistics 
            WHERE suspicious_phrase = %s
        """, (phrase,))
        result = cursor.fetchone()
        return (result['total_occurrences'], result['emails_affected']) if result else (0, 0)
    finally:
        cursor.close()

def test_new_email_creation():
    """Test 1: Creating new emails with phrases"""
    print("\n🧪 Test 1: New email creation")
    
    db = DatabaseService()
    
    # Email 1: phrase1 appears 2 times, phrase2 appears 1 time
    email1_data = {
        'headers': {'subject': 'Test Email 1', 'from': 'test1@example.com', 'to': 'user@example.com'},
        'raw_lines': ['Test email content 1']
    }
    analysis1 = {
        'suspicious_findings': [
            {'phrase': 'urgent_action', 'segment': 'body', 'line_number': 1, 'context': 'urgent action required'},
            {'phrase': 'urgent_action', 'segment': 'body', 'line_number': 2, 'context': 'urgent action needed'},
            {'phrase': 'click_here', 'segment': 'body', 'line_number': 3, 'context': 'click here now'}
        ]
    }
    
    # Email 2: phrase1 appears 1 time, phrase3 appears 3 times
    email2_data = {
        'headers': {'subject': 'Test Email 2', 'from': 'test2@example.com', 'to': 'user@example.com'},
        'raw_lines': ['Test email content 2']
    }
    analysis2 = {
        'suspicious_findings': [
            {'phrase': 'urgent_action', 'segment': 'body', 'line_number': 1, 'context': 'urgent action'},
            {'phrase': 'limited_time', 'segment': 'body', 'line_number': 2, 'context': 'limited time offer'},
            {'phrase': 'limited_time', 'segment': 'body', 'line_number': 3, 'context': 'limited time deal'},
            {'phrase': 'limited_time', 'segment': 'body', 'line_number': 4, 'context': 'limited time only'}
        ]
    }
    
    email1_id = db.store_flagged_email(email1_data, analysis1)
    email2_id = db.store_flagged_email(email2_data, analysis2)
    
    # Verify statistics
    urgent_total, urgent_emails = get_phrase_stats(db, 'urgent_action')
    click_total, click_emails = get_phrase_stats(db, 'click_here')
    limited_total, limited_emails = get_phrase_stats(db, 'limited_time')
    
    assert urgent_total == 3, f"Expected urgent_action total=3, got {urgent_total}"
    assert urgent_emails == 2, f"Expected urgent_action emails=2, got {urgent_emails}"
    assert click_total == 1, f"Expected click_here total=1, got {click_total}"
    assert click_emails == 1, f"Expected click_here emails=1, got {click_emails}"
    assert limited_total == 3, f"Expected limited_time total=3, got {limited_total}"
    assert limited_emails == 1, f"Expected limited_time emails=1, got {limited_emails}"
    
    print("✅ New email creation works correctly")
    db.close()
    return email1_id, email2_id

def test_reanalysis_scenarios(email1_id, email2_id):
    """Test 2: Re-analyzing existing emails"""
    print("\n🧪 Test 2: Email re-analysis scenarios")
    
    db = DatabaseService()
    
    # Get original email data
    email1_data = {
        'headers': {'subject': 'Test Email 1', 'from': 'test1@example.com', 'to': 'user@example.com'},
        'raw_lines': ['Test email content 1']
    }
    
    # Re-analyze email1 with different findings:
    # - urgent_action: was 2, now 1 (decrease by 1)
    # - click_here: was 1, now 0 (phrase removed completely)
    # - new_phrase: was 0, now 2 (new phrase added)
    new_analysis1 = {
        'suspicious_findings': [
            {'phrase': 'urgent_action', 'segment': 'body', 'line_number': 1, 'context': 'urgent action required'},
            {'phrase': 'new_phrase', 'segment': 'body', 'line_number': 2, 'context': 'new suspicious content'},
            {'phrase': 'new_phrase', 'segment': 'body', 'line_number': 3, 'context': 'another new content'}
        ]
    }
    
    # Store before re-analysis
    before_urgent_total, before_urgent_emails = get_phrase_stats(db, 'urgent_action')
    before_click_total, before_click_emails = get_phrase_stats(db, 'click_here')
    before_new_total, before_new_emails = get_phrase_stats(db, 'new_phrase')
    
    # Re-analyze
    db.store_flagged_email(email1_data, new_analysis1)
    
    # Verify statistics after re-analysis
    after_urgent_total, after_urgent_emails = get_phrase_stats(db, 'urgent_action')
    after_click_total, after_click_emails = get_phrase_stats(db, 'click_here')
    after_new_total, after_new_emails = get_phrase_stats(db, 'new_phrase')
    
    # urgent_action: should decrease by 1 (was 2 in email1, now 1)
    assert after_urgent_total == before_urgent_total - 1, f"urgent_action total: expected {before_urgent_total - 1}, got {after_urgent_total}"
    assert after_urgent_emails == before_urgent_emails, f"urgent_action emails should stay same: expected {before_urgent_emails}, got {after_urgent_emails}"
    
    # click_here: should decrease by 1 total and 1 email (phrase completely removed from email1)
    assert after_click_total == before_click_total - 1, f"click_here total: expected {before_click_total - 1}, got {after_click_total}"
    assert after_click_emails == before_click_emails - 1, f"click_here emails: expected {before_click_emails - 1}, got {after_click_emails}"
    
    # new_phrase: should increase by 2 total and 1 email (new phrase in email1)
    assert after_new_total == before_new_total + 2, f"new_phrase total: expected {before_new_total + 2}, got {after_new_total}"
    assert after_new_emails == before_new_emails + 1, f"new_phrase emails: expected {before_new_emails + 1}, got {after_new_emails}"
    
    print("✅ Email re-analysis works correctly")
    db.close()

def test_deletion_scenarios(email1_id, email2_id):
    """Test 3: Individual analysis result deletion"""
    print("\n🧪 Test 3: Individual analysis result deletion")
    
    db = DatabaseService()
    
    # Get an analysis result to delete
    results = db.get_analysis_results(email2_id)
    limited_time_result = next((r for r in results if r['suspicious_phrase'] == 'limited_time'), None)
    
    if limited_time_result:
        before_total, before_emails = get_phrase_stats(db, 'limited_time')
        
        # Delete one occurrence
        db.delete_analysis_result(limited_time_result['id'])
        
        after_total, after_emails = get_phrase_stats(db, 'limited_time')
        
        # Should decrease total by 1, but emails_affected should stay same (still has other occurrences)
        assert after_total == before_total - 1, f"limited_time total: expected {before_total - 1}, got {after_total}"
        assert after_emails == before_emails, f"limited_time emails should stay same: expected {before_emails}, got {after_emails}"
        
        print("✅ Individual analysis result deletion works correctly")
    
    db.close()

def test_email_deletion(email1_id, email2_id):
    """Test 4: Complete email deletion"""
    print("\n🧪 Test 4: Complete email deletion")
    
    db = DatabaseService()
    
    # Get before stats
    before_urgent_total, before_urgent_emails = get_phrase_stats(db, 'urgent_action')
    before_new_total, before_new_emails = get_phrase_stats(db, 'new_phrase')
    
    # Delete email1 (which has urgent_action=1, new_phrase=2)
    db.delete_flagged_email(email1_id)
    
    # Verify statistics updated
    after_urgent_total, after_urgent_emails = get_phrase_stats(db, 'urgent_action')
    after_new_total, after_new_emails = get_phrase_stats(db, 'new_phrase')
    
    # urgent_action should decrease by 1 total and 1 email
    assert after_urgent_total == before_urgent_total - 1, f"urgent_action total: expected {before_urgent_total - 1}, got {after_urgent_total}"
    assert after_urgent_emails == before_urgent_emails - 1, f"urgent_action emails: expected {before_urgent_emails - 1}, got {after_urgent_emails}"
    
    # new_phrase should decrease by 2 total and 1 email (completely removed)
    assert after_new_total == before_new_total - 2, f"new_phrase total: expected {before_new_total - 2}, got {after_new_total}"
    assert after_new_emails == before_new_emails - 1, f"new_phrase emails: expected {before_new_emails - 1}, got {after_new_emails}"
    
    print("✅ Complete email deletion works correctly")
    db.close()

def test_cleanup_operations():
    """Test 5: Cleanup old data operations"""
    print("\n🧪 Test 5: Data cleanup operations")
    
    db = DatabaseService()
    
    # Create an old email for cleanup testing
    old_email_data = {
        'headers': {'subject': 'Old Email', 'from': 'old@example.com', 'to': 'user@example.com'},
        'raw_lines': ['Old email content']
    }
    old_analysis = {
        'suspicious_findings': [
            {'phrase': 'cleanup_test', 'segment': 'body', 'line_number': 1, 'context': 'cleanup test phrase'},
            {'phrase': 'cleanup_test', 'segment': 'body', 'line_number': 2, 'context': 'another cleanup test'}
        ]
    }
    
    old_email_id = db.store_flagged_email(old_email_data, old_analysis)
    
    # Artificially age the email
    cursor = db._get_cursor()
    old_date = datetime.now() - timedelta(days=31)
    cursor.execute("""
        UPDATE flagged_emails SET flagged_at = %s WHERE id = %s
    """, (old_date, old_email_id))
    cursor.close()
    
    # Get before stats
    before_cleanup_total, before_cleanup_emails = get_phrase_stats(db, 'cleanup_test')
    
    # Cleanup old data (30 days)
    cleanup_result = db.cleanup_old_data(days_old=30)
    
    # Verify statistics updated
    after_cleanup_total, after_cleanup_emails = get_phrase_stats(db, 'cleanup_test')
    
    # cleanup_test should be completely removed
    assert after_cleanup_total == 0, f"cleanup_test total should be 0, got {after_cleanup_total}"
    assert after_cleanup_emails == 0, f"cleanup_test emails should be 0, got {after_cleanup_emails}"
    assert cleanup_result['emails_deleted'] >= 1, f"Should have deleted at least 1 email, got {cleanup_result['emails_deleted']}"
    
    print("✅ Data cleanup operations work correctly")
    db.close()

def run_all_tests():
    """Run comprehensive data integrity tests"""
    print("🚀 Starting comprehensive data integrity tests...")
    
    try:
        # Setup
        setup_test_database()
        
        # Test scenarios
        email1_id, email2_id = test_new_email_creation()
        test_reanalysis_scenarios(email1_id, email2_id)
        test_deletion_scenarios(email1_id, email2_id)
        test_email_deletion(email1_id, email2_id)
        test_cleanup_operations()
        
        print("\n🎉 All data integrity tests PASSED!")
        print("✅ Phrase statistics maintain perfect accuracy across all operations")
        return True
        
    except Exception as e:
        print(f"\n❌ Test FAILED: {str(e)}")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)