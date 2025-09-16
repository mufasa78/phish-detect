"""
Phishing Email Detection Package

A comprehensive phishing email detection system with advanced parsing capabilities.
"""

__version__ = "1.0.0"
__author__ = "Mufasa"

# Import main modules for easy access
from .phishing_detector import PhishingDetector
from .email_parser import EmailParser
from .advanced_parser import AdvancedEmailParser, SegmentType, AdvancedSegment
from .database_service import DatabaseService

__all__ = [
    "PhishingDetector",
    "EmailParser", 
    "AdvancedEmailParser",
    "SegmentType",
    "AdvancedSegment",
    "DatabaseService"
]
