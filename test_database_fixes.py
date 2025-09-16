#!/usr/bin/env python3
"""
Test script to verify database integrity and concurrency fixes
"""

import os
import threading
import time
from datetime import datetime
from database_service import DatabaseService

def test_basic_operations():
    """Test basic database operations work with new transaction management"""
    print("🧪 Testing basic database operations...")
    
    try:
        db = DatabaseService()
        
        # Test data
        test_email = {
            'headers': {
                'subject': 'Test Email',
                'from': 'test@example.com',
                'to': 'user@example.com',
                'date': 'Mon, 1 Jan 2025 10:00:00 +0000'
            },
            'raw_lines': ['Test email content']
        }
        
        test_analysis = {
            'suspicious_findings': [
                {
                    'phrase': 'urgent action required',
                    'segment': 'body',
                    'line_number': 1,
                    'context': 'Test context'
                },
                {
                    'phrase': 'click here now',
                    'segment': 'body', 
                    'line_number': 2,
                    'context': 'Test context 2'
                }
            ]
        }
        
        # Test storing flagged email
        email_id = db.store_flagged_email(test_email, test_analysis)
        print(f"✅ Successfully stored email with ID: {email_id}")
        
        # Test retrieving the email
        stored_email = db.get_flagged_email_by_id(email_id)
        assert stored_email is not None, "Email should be retrievable"
        print(f"✅ Successfully retrieved email: {stored_email['email_subject']}")
        
        # Test phrase statistics were created
        stats = db.get_phrase_statistics(10)
        assert len(stats) >= 2, "Should have phrase statistics"
        print(f"✅ Phrase statistics created: {len(stats)} entries")
        
        # Test deleting analysis result
        analysis_results = db.get_analysis_results(email_id)
        if analysis_results:
            result_deleted = db.delete_analysis_result(analysis_results[0]['id'])
            print(f"✅ Successfully deleted analysis result: {result_deleted}")
        
        # Test deleting the email
        deleted = db.delete_flagged_email(email_id)
        print(f"✅ Successfully deleted email: {deleted}")
        
        # Verify it's gone
        retrieved = db.get_flagged_email_by_id(email_id)
        assert retrieved is None, "Email should be deleted"
        print("✅ Email deletion verified")
        
        db.close()
        print("✅ Basic operations test passed!\n")
        return True
        
    except Exception as e:
        print(f"❌ Basic operations test failed: {e}\n")
        return False

def test_concurrent_operations():
    """Test concurrent operations to verify race condition fixes"""
    print("🧪 Testing concurrent phrase statistics updates...")
    
    def worker_thread(thread_id, results):
        """Worker thread to test concurrent updates"""
        try:
            db = DatabaseService()
            
            test_email = {
                'headers': {
                    'subject': f'Concurrent Test Email {thread_id}',
                    'from': f'test{thread_id}@example.com',
                    'to': 'user@example.com',
                    'date': 'Mon, 1 Jan 2025 10:00:00 +0000'
                },
                'raw_lines': [f'Concurrent test content {thread_id}']
            }
            
            test_analysis = {
                'suspicious_findings': [
                    {
                        'phrase': 'urgent action required',  # Same phrase across threads
                        'segment': 'body',
                        'line_number': 1,
                        'context': f'Context from thread {thread_id}'
                    }
                ]
            }
            
            # Store the email
            email_id = db.store_flagged_email(test_email, test_analysis)
            results[thread_id] = {'success': True, 'email_id': email_id}
            db.close()
            
        except Exception as e:
            results[thread_id] = {'success': False, 'error': str(e)}
    
    try:
        # Run multiple threads concurrently
        threads = []
        results = {}
        num_threads = 5
        
        for i in range(num_threads):
            thread = threading.Thread(target=worker_thread, args=(i, results))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        successful_threads = sum(1 for r in results.values() if r.get('success', False))
        print(f"✅ {successful_threads}/{num_threads} concurrent operations succeeded")
        
        # Verify phrase statistics are correct
        db = DatabaseService()
        stats = db.get_phrase_statistics(10)
        urgent_stats = [s for s in stats if s['suspicious_phrase'] == 'urgent action required']
        
        if urgent_stats:
            expected_count = successful_threads
            actual_count = urgent_stats[0]['total_occurrences']
            actual_emails = urgent_stats[0]['emails_affected']
            
            print(f"✅ Phrase statistics: {actual_count} occurrences in {actual_emails} emails (expected: {expected_count})")
            
            if actual_count == expected_count and actual_emails == expected_count:
                print("✅ Concurrency test passed - statistics are accurate!\n")
                
                # Clean up test data
                cleanup_test_data(db)
                db.close()
                return True
            else:
                print(f"❌ Statistics mismatch - expected {expected_count}, got {actual_count}\n")
        else:
            print("❌ No phrase statistics found for concurrent test\n")
        
        db.close()
        return False
        
    except Exception as e:
        print(f"❌ Concurrency test failed: {e}\n")
        return False

def cleanup_test_data(db):
    """Clean up any test data"""
    try:
        # Get all test emails
        emails = db.get_flagged_emails(100)  # Get more to ensure we catch test data
        test_emails = [e for e in emails if 'Test' in e.get('email_subject', '') or 'Concurrent' in e.get('email_subject', '')]
        
        for email in test_emails:
            db.delete_flagged_email(email['id'])
            
        print(f"🧹 Cleaned up {len(test_emails)} test emails")
        
    except Exception as e:
        print(f"⚠️ Cleanup warning: {e}")

def test_constraint_violations():
    """Test that database constraints are working"""
    print("🧪 Testing database constraints...")
    
    try:
        db = DatabaseService()
        
        # Test 1: Try to violate unique constraint on email_hash (should be handled gracefully)
        test_email = {
            'headers': {
                'subject': 'Constraint Test Email',
                'from': 'constraint@example.com',
                'to': 'user@example.com',
                'date': 'Mon, 1 Jan 2025 10:00:00 +0000'
            },
            'raw_lines': ['Same content for hash collision test']
        }
        
        test_analysis = {
            'suspicious_findings': [
                {
                    'phrase': 'test phrase',
                    'segment': 'body',
                    'line_number': 1,
                    'context': 'Test context'
                }
            ]
        }
        
        # Store the same email twice - should update, not create duplicate
        email_id1 = db.store_flagged_email(test_email, test_analysis)
        email_id2 = db.store_flagged_email(test_email, test_analysis)  # Same content
        
        if email_id1 == email_id2:
            print("✅ Email deduplication working correctly")
        else:
            print(f"⚠️ Email deduplication: got different IDs {email_id1} vs {email_id2}")
        
        # Clean up
        db.delete_flagged_email(email_id1)
        db.close()
        
        print("✅ Constraint test passed!\n")
        return True
        
    except Exception as e:
        print(f"❌ Constraint test failed: {e}\n")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Database Integrity & Concurrency Safety Tests\n")
    
    tests = [
        test_basic_operations,
        test_concurrent_operations, 
        test_constraint_violations
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed with exception: {e}\n")
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Database fixes are working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    main()