import psycopg2
import psycopg2.extras
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import pandas as pd
from email.utils import parsedate_to_datetime
import email.utils
from dotenv import load_dotenv


class DatabaseService:
    """Service for managing phishing detection database operations"""
    
    def __init__(self):
        # Load environment variables from .env.local file
        load_dotenv('.env.local')
        self.connection = None
        self._connect()
    
    def _connect(self):
        """Establish database connection with manual transaction control"""
        try:
            self.connection = psycopg2.connect(
                database=os.getenv('PGDATABASE'),
                user=os.getenv('PGUSER'),
                password=os.getenv('PGPASSWORD'),
                host=os.getenv('PGHOST'),
                port=os.getenv('PGPORT')
            )
            # Disable autocommit for proper transaction management
            self.connection.autocommit = False
        except Exception as e:
            raise Exception(f"Failed to connect to database: {str(e)}")
    
    def _get_cursor(self):
        """Get database cursor with dict cursor for easier data handling"""
        if not self.connection or self.connection.closed:
            self._connect()
        if self.connection:
            return self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            raise Exception("Failed to establish database connection")
    
    def _commit_transaction(self):
        """Commit the current transaction"""
        if self.connection and not self.connection.closed:
            self.connection.commit()
    
    def _rollback_transaction(self):
        """Rollback the current transaction"""
        if self.connection and not self.connection.closed:
            self.connection.rollback()
    
    def _execute_in_transaction(self, operation_func, *args, **kwargs):
        """Execute a database operation within a transaction"""
        try:
            result = operation_func(*args, **kwargs)
            self._commit_transaction()
            return result
        except Exception as e:
            self._rollback_transaction()
            raise e
    
    def _generate_email_hash(self, email_content: str) -> str:
        """Generate SHA-256 hash of email content for deduplication"""
        return hashlib.sha256(email_content.encode('utf-8')).hexdigest()
    
    def store_flagged_email(self, parsed_email: Dict, analysis_results: Dict) -> int:
        """
        Store a flagged email and its analysis results in a transaction
        
        Args:
            parsed_email (Dict): Parsed email data
            analysis_results (Dict): Analysis results from phishing detection
            
        Returns:
            int: ID of stored flagged email
        """
        return self._execute_in_transaction(self._store_flagged_email_impl, parsed_email, analysis_results)
    
    def _store_flagged_email_impl(self, parsed_email: Dict, analysis_results: Dict) -> int:
        """Implementation of store_flagged_email within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # Generate email hash for deduplication
            email_content = str(parsed_email.get('raw_lines', []))
            email_hash = self._generate_email_hash(email_content)
            
            # Extract email metadata
            headers = parsed_email.get('headers', {})
            subject = headers.get('subject', '')[:500]  # Truncate to fit column
            from_addr = headers.get('from', '')[:200]
            to_addr = headers.get('to', '')[:200]
            
            # Parse email date
            email_date = None
            if headers.get('date'):
                try:
                    # Parse RFC 2822 date format from email headers
                    email_date = parsedate_to_datetime(headers['date'])
                except (ValueError, TypeError):
                    # If parsing fails, use current timestamp as fallback
                    email_date = datetime.now()
            else:
                email_date = datetime.now()
            
            # Use atomic INSERT ... ON CONFLICT for concurrency-safe deduplication
            cursor.execute("""
                INSERT INTO flagged_emails 
                (email_hash, email_subject, email_from, email_to, email_date, 
                 total_suspicious_findings, email_content, flagged_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (email_hash) 
                DO UPDATE SET 
                    total_suspicious_findings = %s,
                    flagged_at = CURRENT_TIMESTAMP
                RETURNING id, 
                    (CASE WHEN xmax = 0 THEN true ELSE false END) as is_new_email
            """, (email_hash, subject, from_addr, to_addr, email_date, 
                 len(analysis_results.get('suspicious_findings', [])), email_content,
                 len(analysis_results.get('suspicious_findings', []))))
            
            result = cursor.fetchone()
            if result:
                flagged_email_id = result['id']
                is_new_email = result['is_new_email']
            else:
                raise Exception("Failed to insert/update flagged email")
            
            # CRITICAL FIX: Lock the flagged_emails row to serialize per-email writes
            # This prevents concurrent requests for the same email from simultaneously
            # modifying analysis_results and phrase_statistics, avoiding race conditions
            cursor.execute("SELECT id FROM flagged_emails WHERE id = %s FOR UPDATE", (flagged_email_id,))
            
            # Store analysis results with proper phrase statistics handling
            if is_new_email:
                # For new emails, store analysis results normally
                self._store_analysis_results(cursor, flagged_email_id, analysis_results, is_new_email)
            else:
                # For existing emails, compute delta changes to maintain data integrity
                # Get old phrase counts before deletion to compute proper deltas
                cursor.execute("""
                    SELECT suspicious_phrase, COUNT(*) as count 
                    FROM analysis_results 
                    WHERE flagged_email_id = %s
                    GROUP BY suspicious_phrase
                """, (flagged_email_id,))
                old_phrase_counts = {row['suspicious_phrase']: row['count'] for row in cursor.fetchall()}
                
                # Clear existing analysis results
                cursor.execute("""
                    DELETE FROM analysis_results WHERE flagged_email_id = %s
                """, (flagged_email_id,))
                
                # Store new results with old counts for delta computation
                self._store_analysis_results(cursor, flagged_email_id, analysis_results, is_new_email, old_phrase_counts)
            
            return flagged_email_id
            
        except Exception as e:
            raise Exception(f"Failed to store flagged email: {str(e)}")
        finally:
            cursor.close()
    
    def _store_analysis_results(self, cursor, flagged_email_id: int, analysis_results: Dict, is_new_email: bool = True, old_phrase_counts: Optional[Dict[str, int]] = None):
        """Store detailed analysis results for a flagged email"""
        
        # Track new phrase counts for this email to compute deltas
        new_phrase_counts = {}
        old_phrase_counts = old_phrase_counts or {}
        
        for finding in analysis_results.get('suspicious_findings', []):
            phrase = finding.get('phrase', '')[:500]
            segment = finding.get('segment', '')[:100]
            line_number = finding.get('line_number')
            context = finding.get('context', '')
            
            # Insert analysis result with explicit timestamp
            cursor.execute("""
                INSERT INTO analysis_results 
                (flagged_email_id, suspicious_phrase, segment_type, line_number, context_content, created_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (flagged_email_id, phrase, segment, line_number, context))
            
            # Count new occurrences per phrase
            new_phrase_counts[phrase] = new_phrase_counts.get(phrase, 0) + 1
        
        # Update phrase statistics with proper delta computation
        all_phrases = set(new_phrase_counts.keys()) | set(old_phrase_counts.keys())
        for phrase in all_phrases:
            old_count = old_phrase_counts.get(phrase, 0)
            new_count = new_phrase_counts.get(phrase, 0)
            self._update_phrase_statistics_with_delta(cursor, phrase, old_count, new_count, is_new_email)
    
    def _update_phrase_statistics_with_delta(self, cursor, phrase: str, old_count: int, new_count: int, is_new_email: bool):
        """Update phrase statistics using delta computation with concurrency safety"""
        
        count_delta = new_count - old_count
        
        # Determine emails_affected change
        if is_new_email:
            # New email: increment emails_affected if phrase appears
            emails_affected_delta = 1 if new_count > 0 else 0
        else:
            # Re-analyzed email: increment if phrase now appears but didn't before
            # decrement if phrase was there but now gone
            if old_count == 0 and new_count > 0:
                emails_affected_delta = 1  # phrase added to email
            elif old_count > 0 and new_count == 0:
                emails_affected_delta = -1  # phrase removed from email
            else:
                emails_affected_delta = 0  # phrase count changed but still present/absent
        
        # Use UPSERT with row-level locking to handle concurrency safely
        # Only update last_seen when there are positive changes (analytics accuracy)
        if count_delta > 0 or emails_affected_delta > 0:
            cursor.execute("""
                INSERT INTO phrase_statistics 
                (suspicious_phrase, total_occurrences, emails_affected, last_seen)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (suspicious_phrase) 
                DO UPDATE SET 
                    total_occurrences = phrase_statistics.total_occurrences + %s,
                    emails_affected = phrase_statistics.emails_affected + %s,
                    last_seen = CURRENT_TIMESTAMP
            """, (phrase, new_count, emails_affected_delta, count_delta, emails_affected_delta))
        else:
            # For zero or negative deltas, don't update last_seen timestamp
            cursor.execute("""
                INSERT INTO phrase_statistics 
                (suspicious_phrase, total_occurrences, emails_affected, last_seen)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (suspicious_phrase) 
                DO UPDATE SET 
                    total_occurrences = phrase_statistics.total_occurrences + %s,
                    emails_affected = phrase_statistics.emails_affected + %s
            """, (phrase, new_count, emails_affected_delta, count_delta, emails_affected_delta))
        
        # Clean up statistics entries that are no longer relevant (total counts <= 0)
        if count_delta < 0 or emails_affected_delta < 0:
            cursor.execute("""
                DELETE FROM phrase_statistics 
                WHERE suspicious_phrase = %s 
                  AND total_occurrences <= 0 
                  AND emails_affected <= 0
            """, (phrase,))
    
    def _decrement_phrase_statistics(self, cursor, phrase: str, occurrence_decrement: int, emails_affected_decrement: int = 0):
        """Decrement phrase statistics atomically when analysis results are deleted"""
        
        # Use atomic UPDATE with conditional deletion for concurrency safety
        # Don't update last_seen on decrements to maintain analytics accuracy
        cursor.execute("""
            UPDATE phrase_statistics 
            SET total_occurrences = total_occurrences - %s,
                emails_affected = emails_affected - %s
            WHERE suspicious_phrase = %s
        """, (occurrence_decrement, emails_affected_decrement, phrase))
        
        # Clean up statistics entries that are no longer relevant (both total counts <= 0)
        cursor.execute("""
            DELETE FROM phrase_statistics 
            WHERE suspicious_phrase = %s 
              AND total_occurrences <= 0 
              AND emails_affected <= 0
        """, (phrase,))
    
    def get_flagged_emails(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get list of flagged emails with pagination"""
        cursor = self._get_cursor()
        
        try:
            # Fix PostgreSQL GROUP BY error by using subquery for finding count
            cursor.execute("""
                SELECT fe.*, 
                       COALESCE(ar_counts.finding_count, 0) as finding_count
                FROM flagged_emails fe
                LEFT JOIN (
                    SELECT flagged_email_id, COUNT(*) as finding_count
                    FROM analysis_results
                    GROUP BY flagged_email_id
                ) ar_counts ON fe.id = ar_counts.flagged_email_id
                ORDER BY fe.flagged_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            
            return [dict(row) for row in cursor.fetchall()]
            
        finally:
            cursor.close()
    
    def get_analysis_results(self, flagged_email_id: int) -> List[Dict]:
        """Get detailed analysis results for a specific email"""
        cursor = self._get_cursor()
        
        try:
            cursor.execute("""
                SELECT * FROM analysis_results 
                WHERE flagged_email_id = %s
                ORDER BY created_at ASC
            """, (flagged_email_id,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        finally:
            cursor.close()
    
    def get_phrase_statistics(self, limit: int = 100) -> List[Dict]:
        """Get statistics about suspicious phrases"""
        cursor = self._get_cursor()
        
        try:
            cursor.execute("""
                SELECT * FROM phrase_statistics 
                ORDER BY total_occurrences DESC, last_seen DESC
                LIMIT %s
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        finally:
            cursor.close()
    
    def get_occurrence_report(self) -> Dict:
        """Generate a comprehensive occurrence report"""
        cursor = self._get_cursor()
        
        try:
            # Get total statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_flagged_emails,
                    SUM(total_suspicious_findings) as total_findings,
                    COUNT(DISTINCT email_hash) as unique_emails
                FROM flagged_emails
            """)
            result = cursor.fetchone()
            totals = dict(result) if result else {}
            
            # Get top phrases
            cursor.execute("""
                SELECT suspicious_phrase, total_occurrences, emails_affected
                FROM phrase_statistics 
                ORDER BY total_occurrences DESC
                LIMIT 10
            """)
            top_phrases = [dict(row) for row in cursor.fetchall()]
            
            # Get recent activity
            cursor.execute("""
                SELECT fe.email_subject, fe.flagged_at, fe.total_suspicious_findings
                FROM flagged_emails fe
                ORDER BY fe.flagged_at DESC
                LIMIT 10
            """)
            recent_emails = [dict(row) for row in cursor.fetchall()]
            
            return {
                'summary': totals,
                'top_phrases': top_phrases,
                'recent_activity': recent_emails,
                'generated_at': datetime.now().isoformat()
            }
            
        finally:
            cursor.close()
    
    def delete_flagged_email(self, email_id: int) -> bool:
        """Delete a flagged email and all its analysis results in a transaction"""
        return self._execute_in_transaction(self._delete_flagged_email_impl, email_id)
    
    def _delete_flagged_email_impl(self, email_id: int) -> bool:
        """Implementation of delete_flagged_email within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # First capture phrase counts before deletion to update statistics
            cursor.execute("""
                SELECT suspicious_phrase, COUNT(*) as count 
                FROM analysis_results 
                WHERE flagged_email_id = %s
                GROUP BY suspicious_phrase
            """, (email_id,))
            phrase_counts_to_remove = {row['suspicious_phrase']: row['count'] for row in cursor.fetchall()}
            
            # Delete all analysis results for this email
            cursor.execute("""
                DELETE FROM analysis_results WHERE flagged_email_id = %s
            """, (email_id,))
            
            # Update phrase statistics by removing the counts
            for phrase, count in phrase_counts_to_remove.items():
                self._decrement_phrase_statistics(cursor, phrase, count, emails_affected_decrement=1)
            
            # Then delete the flagged email
            cursor.execute("""
                DELETE FROM flagged_emails WHERE id = %s
            """, (email_id,))
            
            # Check if the email was actually deleted
            return cursor.rowcount > 0
            
        except Exception as e:
            raise Exception(f"Failed to delete flagged email: {str(e)}")
        finally:
            cursor.close()
    
    def delete_analysis_result(self, result_id: int) -> bool:
        """Delete a specific analysis result in a transaction"""
        return self._execute_in_transaction(self._delete_analysis_result_impl, result_id)
    
    def _delete_analysis_result_impl(self, result_id: int) -> bool:
        """Implementation of delete_analysis_result within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # First get the phrase and check if it's the last occurrence for this email
            cursor.execute("""
                SELECT suspicious_phrase, flagged_email_id FROM analysis_results WHERE id = %s
            """, (result_id,))
            result = cursor.fetchone()
            
            if not result:
                return False
                
            phrase = result['suspicious_phrase']
            email_id = result['flagged_email_id']
            
            # Check if this is the last occurrence of this phrase in this email
            cursor.execute("""
                SELECT COUNT(*) as count FROM analysis_results 
                WHERE flagged_email_id = %s AND suspicious_phrase = %s
            """, (email_id, phrase))
            
            result_count = cursor.fetchone()
            current_count = result_count['count'] if result_count else 0
            is_last_occurrence_in_email = current_count == 1
            
            # Delete the analysis result
            cursor.execute("""
                DELETE FROM analysis_results WHERE id = %s
            """, (result_id,))
            
            deleted = cursor.rowcount > 0
            
            if deleted:
                # Update phrase statistics: decrement by 1, and emails_affected if this was the last occurrence
                emails_affected_decrement = 1 if is_last_occurrence_in_email else 0
                self._decrement_phrase_statistics(cursor, phrase, 1, emails_affected_decrement)
            
            return deleted
            
        except Exception as e:
            raise Exception(f"Failed to delete analysis result: {str(e)}")
        finally:
            cursor.close()
    
    def delete_phrase_statistic(self, phrase_id: int) -> bool:
        """Delete a phrase statistic entry"""
        return self._execute_in_transaction(self._delete_phrase_statistic_impl, phrase_id)
    
    def _delete_phrase_statistic_impl(self, phrase_id: int) -> bool:
        """Implementation of delete_phrase_statistic within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            cursor.execute("""
                DELETE FROM phrase_statistics WHERE id = %s
            """, (phrase_id,))
            
            return cursor.rowcount > 0
            
        except Exception as e:
            raise Exception(f"Failed to delete phrase statistic: {str(e)}")
        finally:
            cursor.close()
    
    def update_flagged_email(self, email_id: int, updates: Dict) -> bool:
        """Update a flagged email with provided fields"""
        return self._execute_in_transaction(self._update_flagged_email_impl, email_id, updates)
    
    def _update_flagged_email_impl(self, email_id: int, updates: Dict) -> bool:
        """Implementation of update_flagged_email within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # Build dynamic update query based on provided fields
            valid_fields = {
                'email_subject', 'email_from', 'email_to', 'email_date', 
                'total_suspicious_findings', 'email_content', 'risk_level'
            }
            
            update_fields = {k: v for k, v in updates.items() if k in valid_fields}
            
            if not update_fields:
                return False
            
            # Build SET clause
            set_clause = ", ".join([f"{field} = %s" for field in update_fields.keys()])
            values = list(update_fields.values()) + [email_id]
            
            cursor.execute(f"""
                UPDATE flagged_emails 
                SET {set_clause}
                WHERE id = %s
            """, values)
            
            return cursor.rowcount > 0
            
        except Exception as e:
            raise Exception(f"Failed to update flagged email: {str(e)}")
        finally:
            cursor.close()
    
    def update_analysis_result(self, result_id: int, updates: Dict) -> bool:
        """Update an analysis result with provided fields"""
        return self._execute_in_transaction(self._update_analysis_result_impl, result_id, updates)
    
    def _update_analysis_result_impl(self, result_id: int, updates: Dict) -> bool:
        """Implementation of update_analysis_result within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # Build dynamic update query based on provided fields
            valid_fields = {
                'suspicious_phrase', 'segment_type', 'line_number', 'context_content'
            }
            
            update_fields = {k: v for k, v in updates.items() if k in valid_fields}
            
            if not update_fields:
                return False
            
            # Build SET clause
            set_clause = ", ".join([f"{field} = %s" for field in update_fields.keys()])
            values = list(update_fields.values()) + [result_id]
            
            cursor.execute(f"""
                UPDATE analysis_results 
                SET {set_clause}
                WHERE id = %s
            """, values)
            
            return cursor.rowcount > 0
            
        except Exception as e:
            raise Exception(f"Failed to update analysis result: {str(e)}")
        finally:
            cursor.close()
    
    def get_flagged_email_by_id(self, email_id: int) -> Optional[Dict]:
        """Get a specific flagged email by ID"""
        cursor = self._get_cursor()
        
        try:
            cursor.execute("""
                SELECT fe.*, 
                       COALESCE(ar_counts.finding_count, 0) as finding_count
                FROM flagged_emails fe
                LEFT JOIN (
                    SELECT flagged_email_id, COUNT(*) as finding_count
                    FROM analysis_results
                    GROUP BY flagged_email_id
                ) ar_counts ON fe.id = ar_counts.flagged_email_id
                WHERE fe.id = %s
            """, (email_id,))
            
            result = cursor.fetchone()
            return dict(result) if result else None
            
        finally:
            cursor.close()
    
    def get_flagged_email_count(self) -> int:
        """Get total count of flagged emails"""
        cursor = self._get_cursor()
        
        try:
            cursor.execute("""
                SELECT COUNT(*) as count FROM flagged_emails
            """)
            
            result = cursor.fetchone()
            return result['count'] if result else 0
            
        finally:
            cursor.close()
    
    def cleanup_old_data(self, days_old: int = 30) -> Dict[str, int]:
        """Clean up old flagged emails and related data in a transaction"""
        return self._execute_in_transaction(self._cleanup_old_data_impl, days_old)
    
    def _cleanup_old_data_impl(self, days_old: int = 30) -> Dict[str, int]:
        """Implementation of cleanup_old_data within transaction boundary"""
        cursor = self._get_cursor()
        
        try:
            # Count what will be deleted using proper interval syntax
            cursor.execute("""
                SELECT COUNT(*) as count FROM flagged_emails 
                WHERE flagged_at < NOW() - make_interval(days => %s)
            """, (days_old,))
            
            result = cursor.fetchone()
            old_emails_count = result['count'] if result else 0
            
            # Capture phrase statistics before deletion
            cursor.execute("""
                SELECT ar.suspicious_phrase, 
                       COUNT(*) as total_occurrences,
                       COUNT(DISTINCT ar.flagged_email_id) as emails_affected
                FROM analysis_results ar
                JOIN flagged_emails fe ON ar.flagged_email_id = fe.id
                WHERE fe.flagged_at < NOW() - make_interval(days => %s)
                GROUP BY ar.suspicious_phrase
            """, (days_old,))
            
            phrases_to_update = [(row['suspicious_phrase'], row['total_occurrences'], row['emails_affected']) 
                               for row in cursor.fetchall()]
            
            # Delete old analysis results first using proper interval syntax
            cursor.execute("""
                DELETE FROM analysis_results 
                WHERE flagged_email_id IN (
                    SELECT id FROM flagged_emails 
                    WHERE flagged_at < NOW() - make_interval(days => %s)
                )
            """, (days_old,))
            
            analysis_deleted = cursor.rowcount
            
            # Update phrase statistics for the deleted data
            for phrase, total_occurrences, emails_affected in phrases_to_update:
                self._decrement_phrase_statistics(cursor, phrase, total_occurrences, emails_affected)
            
            # Delete old flagged emails using proper interval syntax
            cursor.execute("""
                DELETE FROM flagged_emails 
                WHERE flagged_at < NOW() - make_interval(days => %s)
            """, (days_old,))
            
            emails_deleted = cursor.rowcount
            
            return {
                'emails_deleted': emails_deleted,
                'analysis_results_deleted': analysis_deleted,
                'days_old': days_old
            }
            
        except Exception as e:
            raise Exception(f"Failed to cleanup old data: {str(e)}")
        finally:
            cursor.close()
    
    def close(self):
        """Close database connection"""
        if self.connection and not self.connection.closed:
            self.connection.close()