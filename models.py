from app import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)  # 'website', 'email', 'infrastructure'
    status = db.Column(db.String(20), default='pending')  # 'pending', 'in_progress', 'completed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    results = db.relationship('ScanResult', backref='scan', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Scan {self.id} - {self.target}>'


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))  # 'low', 'medium', 'high', 'critical'
    description = db.Column(db.Text)
    details = db.Column(db.Text)
    remediation = db.Column(db.Text)
    exploitation = db.Column(db.Text)
    
    def __repr__(self):
        return f'<ScanResult {self.id} - {self.vulnerability_type}>'


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    format = db.Column(db.String(10))  # 'pdf', 'csv'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan = db.relationship('Scan', backref='reports')
    
    def __repr__(self):
        return f'<Report {self.id} - {self.format}>'


# Security framework integration models
class SecurityFramework(db.Model):
    """Model for storing different security frameworks like OWASP, NIST, etc."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    version = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    website = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    controls = db.relationship('FrameworkControl', backref='framework', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<SecurityFramework {self.name} {self.version}>'


class FrameworkControl(db.Model):
    """Model for storing controls/requirements within security frameworks"""
    id = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey('security_framework.id'), nullable=False)
    control_id = db.Column(db.String(50), nullable=False)  # e.g., "A1:2017" for OWASP
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # 'low', 'medium', 'high', 'critical'
    category = db.Column(db.String(100))
    mappings = db.relationship('VulnerabilityMapping', backref='control', lazy='dynamic', cascade="all, delete-orphan")
    
    __table_args__ = (db.UniqueConstraint('framework_id', 'control_id', name='unique_control_per_framework'),)
    
    def __repr__(self):
        return f'<FrameworkControl {self.control_id} - {self.name}>'


class VulnerabilityMapping(db.Model):
    """Model for mapping vulnerability types to framework controls"""
    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.Integer, db.ForeignKey('framework_control.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    mapping_confidence = db.Column(db.String(20), default='high')  # 'low', 'medium', 'high'
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('control_id', 'vulnerability_type', name='unique_vuln_control_mapping'),)
    
    def __repr__(self):
        return f'<VulnerabilityMapping {self.vulnerability_type} to Control {self.control_id}>'


class ComplianceReport(db.Model):
    """Model for storing compliance reports for scans"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    framework_id = db.Column(db.Integer, db.ForeignKey('security_framework.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    compliance_score = db.Column(db.Float)  # Percentage of compliance
    details = db.Column(db.Text)  # JSON string containing detailed mapping results
    scan = db.relationship('Scan')
    framework = db.relationship('SecurityFramework')
    
    def __repr__(self):
        return f'<ComplianceReport {self.id} - Score: {self.compliance_score}%>'
    
    def get_detailed_results(self):
        """Return the details as a Python dictionary"""
        if self.details:
            return json.loads(self.details)
        return {}
