import streamlit as st
import pandas as pd
import io
from email_parser import EmailParser
from phishing_detector import PhishingDetector

# Import database service with error handling for deployment
try:
    from database_service import DatabaseService
    DATABASE_AVAILABLE = True
except Exception as e:
    st.error(f"Database connection issue: {str(e)}")
    DATABASE_AVAILABLE = False

def main():
    st.set_page_config(
        page_title="Phishing Email Detector",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Phishing Email Detection Tool")
    st.markdown("### Analyze emails for suspicious content and potential phishing attempts")
    
    # Sidebar for file uploads
    st.sidebar.header("📁 File Uploads")
    
    # Setup file upload
    st.sidebar.subheader("1. Upload Setup File")
    st.sidebar.markdown("Upload a CSV or Excel file with suspicious words/phrases")
    setup_file = st.sidebar.file_uploader(
        "Choose setup file",
        type=['csv', 'xlsx', 'xls'],
        help="File should contain 3 columns: start_segment, end_segment, suspicious_phrase"
    )
    
    # Email file upload
    st.sidebar.subheader("2. Upload Email File")
    st.sidebar.markdown("Upload an .eml email file to analyze")
    email_file = st.sidebar.file_uploader(
        "Choose email file",
        type=['eml'],
        help="Upload an .eml email file for phishing analysis"
    )
    
    # Main content area
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📋 Setup File Preview")
        if setup_file is not None:
            try:
                # Read setup file
                if setup_file.name.endswith('.csv'):
                    setup_df = pd.read_csv(setup_file)
                else:
                    setup_df = pd.read_excel(setup_file)
                
                # Validate setup file structure
                expected_columns = ['start_segment', 'end_segment', 'suspicious_phrase']
                if len(setup_df.columns) >= 3:
                    # Rename columns to expected names if they don't match
                    setup_df.columns = expected_columns[:len(setup_df.columns)]
                    st.success(f"✅ Setup file loaded: {len(setup_df)} rules")
                    st.dataframe(setup_df, use_container_width=True)
                else:
                    st.error("❌ Setup file must have at least 3 columns: start_segment, end_segment, suspicious_phrase")
                    setup_df = None
            except Exception as e:
                st.error(f"❌ Error reading setup file: {str(e)}")
                setup_df = None
        else:
            st.info("📤 Please upload a setup file to begin")
            setup_df = None
    
    with col2:
        st.subheader("📧 Email File Preview")
        if email_file is not None:
            try:
                # Read email file content
                email_content = email_file.read().decode('utf-8')
                st.success("✅ Email file loaded successfully")
                
                # Show first few lines of email
                lines = email_content.split('\n')
                preview_lines = lines[:10]
                st.text_area(
                    "Email Preview (first 10 lines)",
                    '\n'.join(preview_lines),
                    height=200,
                    disabled=True
                )
                
                if len(lines) > 10:
                    st.info(f"📊 Email contains {len(lines)} total lines")
                
            except Exception as e:
                st.error(f"❌ Error reading email file: {str(e)}")
                email_content = None
        else:
            st.info("📤 Please upload an email file to analyze")
            email_content = None
    
    # Database Statistics Section
    st.markdown("---")
    st.subheader("📊 Database Statistics")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("📈 View Database Report", help="View statistics about stored phishing detections"):
            if not DATABASE_AVAILABLE:
                st.error("❌ Database service is not available. Please check configuration.")
            else:
                try:
                    db_service = DatabaseService()
                    report = db_service.get_occurrence_report()
                    
                    # Display summary statistics
                    summary = report.get('summary', {})
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Total Flagged Emails", summary.get('total_flagged_emails', 0))
                    with col_b:
                        st.metric("Total Findings", summary.get('total_findings', 0))
                    with col_c:
                        st.metric("Unique Emails", summary.get('unique_emails', 0))
                    
                    # Top suspicious phrases
                    if report.get('top_phrases'):
                        st.subheader("🎯 Top Suspicious Phrases")
                        phrases_df = pd.DataFrame(report['top_phrases'])
                        st.dataframe(phrases_df, use_container_width=True)
                    
                    # Recent activity
                    if report.get('recent_activity'):
                        st.subheader("⏰ Recent Flagged Emails")
                        recent_df = pd.DataFrame(report['recent_activity'])
                        st.dataframe(recent_df, use_container_width=True)
                    
                    db_service.close()
                    
                except Exception as e:
                    st.error(f"❌ Failed to load database report: {str(e)}")
    
    with col2:
        if st.button("📋 View All Flagged Emails", help="View list of all emails stored in database"):
            if not DATABASE_AVAILABLE:
                st.error("❌ Database service is not available. Please check configuration.")
            else:
                try:
                    db_service = DatabaseService()
                    flagged_emails = db_service.get_flagged_emails(limit=20)
                    
                    if flagged_emails:
                        st.subheader("📧 Recently Flagged Emails")
                        emails_df = pd.DataFrame(flagged_emails)
                        # Select relevant columns for display
                        display_columns = ['id', 'email_subject', 'email_from', 'total_suspicious_findings', 'flagged_at']
                        available_columns = [col for col in display_columns if col in emails_df.columns]
                        st.dataframe(emails_df[available_columns], use_container_width=True)
                    else:
                        st.info("No flagged emails found in database")
                    
                    db_service.close()
                    
                except Exception as e:
                    st.error(f"❌ Failed to load flagged emails: {str(e)}")
    
    # Analysis section
    st.markdown("---")
    st.subheader("🔍 Phishing Analysis")
    
    if setup_df is not None and email_file is not None and email_content is not None:
        if st.button("🚀 Run Phishing Detection", type="primary", use_container_width=True):
            with st.spinner("Analyzing email for phishing indicators..."):
                try:
                    # Parse email
                    parser = EmailParser()
                    parsed_email = parser.parse_email(email_content)
                    
                    # Run phishing detection
                    detector = PhishingDetector(setup_df)
                    results = detector.analyze_email(parsed_email)
                    
                    # Store results in database if suspicious
                    if results['is_suspicious']:
                        if DATABASE_AVAILABLE:
                            try:
                                db_service = DatabaseService()
                                flagged_email_id = db_service.store_flagged_email(parsed_email, results)
                                st.success(f"🗄️ Suspicious email stored in database (ID: {flagged_email_id})")
                                db_service.close()
                            except Exception as db_error:
                                st.warning(f"⚠️ Analysis completed but failed to store in database: {str(db_error)}")
                        else:
                            st.warning("⚠️ Analysis completed but database storage is not available.")
                    
                    # Display results
                    display_results(results, parsed_email)
                    
                except Exception as e:
                    st.error(f"❌ Error during analysis: {str(e)}")
    else:
        st.info("📋 Please upload both setup file and email file to run analysis")

def display_results(results, parsed_email):
    """Display the analysis results"""
    
    # Overall result
    if results['is_suspicious']:
        st.error(f"🚨 **PHISHING DETECTED** - {len(results['suspicious_findings'])} suspicious phrase(s) found")
    else:
        st.success("✅ **EMAIL PASSED** - No suspicious phrases detected")
    
    # Detailed findings
    if results['suspicious_findings']:
        st.subheader("🔍 Suspicious Findings")
        
        for i, finding in enumerate(results['suspicious_findings'], 1):
            with st.expander(f"Finding #{i}: '{finding['phrase']}' in {finding['segment']} segment"):
                st.markdown(f"**Suspicious Phrase:** `{finding['phrase']}`")
                st.markdown(f"**Found in Segment:** `{finding['segment']}`")
                st.markdown(f"**Line Number:** {finding['line_number']}")
                st.markdown(f"**Context:**")
                st.code(finding['context'], language='html' if finding['segment'] == 'body' else 'text')
    
    # Email segments analyzed
    st.subheader("📊 Analysis Summary")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Segments Analyzed", len(results['segments_analyzed']))
    with col2:
        st.metric("Suspicious Findings", len(results['suspicious_findings']))
    with col3:
        st.metric("Risk Level", "HIGH" if results['is_suspicious'] else "LOW")
    
    # Show analyzed segments
    if results['segments_analyzed']:
        st.subheader("📝 Analyzed Email Segments")
        
        for segment_name, segment_info in results['segments_analyzed'].items():
            with st.expander(f"{segment_name.upper()} Segment (Lines {segment_info['start_line']}-{segment_info['end_line']})"):
                st.code(segment_info['content'], language='html' if segment_name == 'body' else 'text')

if __name__ == "__main__":
    main()
