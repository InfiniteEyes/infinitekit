import os
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse
from app import app, db
from utils.compliance_simple import seed_frameworks, get_all_frameworks, generate_compliance_report, get_framework_details, map_vulnerability_to_controls
from models import User, Scan, ScanResult, Report, ComplianceReport, SecurityFramework
from scanners.web_scanner import scan_website
from scanners.email_scanner import scan_email
from scanners.infrastructure_scanner import scan_infrastructure
from utils.reporting import generate_pdf_report, generate_csv_report
from utils.remediation import get_remediation_steps
from utils.exploitation import get_exploitation_details
from datetime import datetime
import threading
import logging


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/quick-scan', methods=['POST'])
@login_required
def quick_scan():
    target_url = request.form.get('target_url')
    
    if not target_url:
        flash('Please enter a URL to scan', 'danger')
        return redirect(url_for('index'))
    
    # Create a new scan record
    new_scan = Scan(
        target=target_url,
        scan_type='website',
        status='pending',
        user_id=current_user.id
    )
    db.session.add(new_scan)
    db.session.commit()
    
    # Start the scan in a separate thread
    def run_scan():
        with app.app_context():  # Add application context for threading
            try:
                new_scan.status = 'in_progress'
                db.session.commit()
                
                # Run the scan with basic depth
                results = scan_website(target_url, 'basic')
                
                # Save results
                for result in results:
                    new_result = ScanResult(
                        scan_id=new_scan.id,
                        vulnerability_type=result['vulnerability_type'],
                        severity=result['severity'],
                        description=result['description'],
                        details=result['details'],
                        remediation=get_remediation_steps(result['vulnerability_type']),
                        exploitation=get_exploitation_details(result['vulnerability_type'])
                    )
                    db.session.add(new_result)
                
                new_scan.status = 'completed'
                new_scan.completed_at = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                logging.error(f"Quick scan error: {e}")
                new_scan.status = 'failed'
                db.session.commit()
    
    threading.Thread(target=run_scan).start()
    
    flash(f'Quick scan for {target_url} has been started! You can check the results on your dashboard.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('dashboard')
        return redirect(next_page)
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Username or email already in use', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(10).all()
    website_scans_count = Scan.query.filter_by(user_id=current_user.id, scan_type='website').count()
    email_scans_count = Scan.query.filter_by(user_id=current_user.id, scan_type='email').count()
    infrastructure_scans_count = Scan.query.filter_by(user_id=current_user.id, scan_type='infrastructure').count()
    
    # Getting statistics for vulnerabilities
    vulnerability_stats = {}
    severity_stats = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    # Get all scans by the current user
    scans = Scan.query.filter_by(user_id=current_user.id).all()
    for scan in scans:
        for result in scan.results:
            # Count by vulnerability type
            if result.vulnerability_type in vulnerability_stats:
                vulnerability_stats[result.vulnerability_type] += 1
            else:
                vulnerability_stats[result.vulnerability_type] = 1
            
            # Count by severity
            if result.severity in severity_stats:
                severity_stats[result.severity] += 1
    
    return render_template(
        'dashboard.html',
        recent_scans=recent_scans,
        website_scans_count=website_scans_count,
        email_scans_count=email_scans_count,
        infrastructure_scans_count=infrastructure_scans_count,
        vulnerability_stats=vulnerability_stats,
        severity_stats=severity_stats
    )


@app.route('/scan/website', methods=['GET', 'POST'])
@login_required
def scan_website_route():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scan_depth = request.form.get('scan_depth', 'basic')
        
        if not target_url:
            flash('Please enter a URL to scan', 'danger')
            return redirect(url_for('scan_website_route'))
        
        # Create a new scan record
        new_scan = Scan(
            target=target_url,
            scan_type='website',
            status='pending',
            user_id=current_user.id
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan in a separate thread
        def run_scan():
            with app.app_context():  # Add application context for threading
                try:
                    new_scan.status = 'in_progress'
                    db.session.commit()
                    
                    # Run the scan
                    results = scan_website(target_url, scan_depth)
                    
                    # Save results
                    for result in results:
                        new_result = ScanResult(
                            scan_id=new_scan.id,
                            vulnerability_type=result['vulnerability_type'],
                            severity=result['severity'],
                            description=result['description'],
                            details=result['details'],
                            remediation=get_remediation_steps(result['vulnerability_type']),
                            exploitation=get_exploitation_details(result['vulnerability_type'])
                        )
                        db.session.add(new_result)
                    
                    new_scan.status = 'completed'
                    new_scan.completed_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Scan error: {e}")
                    new_scan.status = 'failed'
                    db.session.commit()
        
        threading.Thread(target=run_scan).start()
        
        flash(f'Scan for {target_url} has been started! You can check the results soon.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('scan_website.html')


@app.route('/scan/email', methods=['GET', 'POST'])
@login_required
def scan_email_route():
    if request.method == 'POST':
        target_email = request.form.get('target_email')
        scan_headers = 'scan_headers' in request.form
        check_spf_dkim = 'check_spf_dkim' in request.form
        check_phishing = 'check_phishing' in request.form
        
        if not target_email:
            flash('Please enter an email to scan', 'danger')
            return redirect(url_for('scan_email_route'))
        
        # Create a new scan record
        new_scan = Scan(
            target=target_email,
            scan_type='email',
            status='pending',
            user_id=current_user.id
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan in a separate thread
        def run_scan():
            with app.app_context():  # Add application context for threading
                try:
                    new_scan.status = 'in_progress'
                    db.session.commit()
                    
                    # Run the scan
                    results = scan_email(
                        target_email, 
                        scan_headers=scan_headers, 
                        check_spf_dkim=check_spf_dkim,
                        check_phishing=check_phishing
                    )
                    
                    # Save results
                    for result in results:
                        new_result = ScanResult(
                            scan_id=new_scan.id,
                            vulnerability_type=result['vulnerability_type'],
                            severity=result['severity'],
                            description=result['description'],
                            details=result['details'],
                            remediation=get_remediation_steps(result['vulnerability_type']),
                            exploitation=get_exploitation_details(result['vulnerability_type'])
                        )
                        db.session.add(new_result)
                    
                    new_scan.status = 'completed'
                    new_scan.completed_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Email scan error: {e}")
                    new_scan.status = 'failed'
                    db.session.commit()
        
        threading.Thread(target=run_scan).start()
        
        flash(f'Email scan for {target_email} has been started! You can check the results soon.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('scan_email.html')


@app.route('/scan/infrastructure', methods=['GET', 'POST'])
@login_required
def scan_infrastructure_route():
    if request.method == 'POST':
        target_host = request.form.get('target_host')
        port_scan = 'port_scan' in request.form
        service_scan = 'service_scan' in request.form
        
        if not target_host:
            flash('Please enter a host to scan', 'danger')
            return redirect(url_for('scan_infrastructure_route'))
        
        # Create a new scan record
        new_scan = Scan(
            target=target_host,
            scan_type='infrastructure',
            status='pending',
            user_id=current_user.id
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Start the scan in a separate thread
        def run_scan():
            with app.app_context():  # Add application context for threading
                try:
                    new_scan.status = 'in_progress'
                    db.session.commit()
                    
                    # Run the scan
                    results = scan_infrastructure(
                        target_host, 
                        port_scan=port_scan, 
                        service_scan=service_scan
                    )
                    
                    # Save results
                    for result in results:
                        new_result = ScanResult(
                            scan_id=new_scan.id,
                            vulnerability_type=result['vulnerability_type'],
                            severity=result['severity'],
                            description=result['description'],
                            details=result['details'],
                            remediation=get_remediation_steps(result['vulnerability_type']),
                            exploitation=get_exploitation_details(result['vulnerability_type'])
                        )
                        db.session.add(new_result)
                    
                    new_scan.status = 'completed'
                    new_scan.completed_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Infrastructure scan error: {e}")
                    new_scan.status = 'failed'
                    db.session.commit()
        
        threading.Thread(target=run_scan).start()
        
        flash(f'Infrastructure scan for {target_host} has been started! You can check the results soon.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('scan_infrastructure.html')


@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    results = scan.results.all()
    
    # Group vulnerabilities by severity for better visualization
    vulnerabilities_by_severity = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for result in results:
        if result.severity in vulnerabilities_by_severity:
            vulnerabilities_by_severity[result.severity].append(result)
    
    return render_template(
        'report.html',
        scan=scan,
        results=results,
        vulnerabilities_by_severity=vulnerabilities_by_severity
    )


@app.route('/blue-team/<int:scan_id>')
@login_required
def blue_team(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    results = scan.results.all()
    
    return render_template('blue_team.html', scan=scan, results=results)


@app.route('/red-team/<int:scan_id>')
@login_required
def red_team(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to view this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    results = scan.results.all()
    
    return render_template('red_team.html', scan=scan, results=results)


@app.route('/export/<int:scan_id>/<format>')
@login_required
def export_report(scan_id, format):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to export this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    if scan.status != 'completed':
        flash('Cannot export report for an incomplete scan', 'warning')
        return redirect(url_for('view_scan', scan_id=scan_id))
    
    results = scan.results.all()
    
    # Create a new report record
    new_report = Report(
        scan_id=scan_id,
        format=format
    )
    db.session.add(new_report)
    db.session.commit()
    
    if format == 'pdf':
        pdf_path = generate_pdf_report(scan, results)
        return send_file(pdf_path, as_attachment=True, download_name=f'scan_report_{scan_id}.pdf')
    elif format == 'csv':
        csv_path = generate_csv_report(scan, results)
        return send_file(csv_path, as_attachment=True, download_name=f'scan_report_{scan_id}.csv')
    else:
        flash('Unsupported report format', 'danger')
        return redirect(url_for('view_scan', scan_id=scan_id))


@app.route('/scan-status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'status': scan.status,
        'created_at': scan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'completed_at': scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else None
    })


@app.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to delete this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# Security Framework Integration Routes
@app.route('/initialize-frameworks')
@login_required
def initialize_frameworks():
    """Admin route to initialize the security frameworks"""
    # This should only be run once to set up the frameworks
    result = seed_frameworks()
    flash(result, 'info')
    return redirect(url_for('dashboard'))


@app.route('/frameworks/<int:scan_id>')
@login_required
def select_framework(scan_id):
    """Page to select a security framework for compliance reporting"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to access this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    if scan.status != 'completed':
        flash('Cannot generate compliance report for an incomplete scan', 'warning')
        return redirect(url_for('view_scan', scan_id=scan_id))
    
    # Get all available frameworks
    frameworks = get_all_frameworks()
    
    return render_template('frameworks.html', scan=scan, frameworks=frameworks)


@app.route('/compliance/<int:scan_id>/<int:framework_id>')
@login_required
def compliance_report(scan_id, framework_id):
    """Generate and display a compliance report for a scan against a framework"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to access this scan', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get framework details
    framework_details = get_framework_details(framework_id)
    if not framework_details:
        flash('Invalid security framework selected', 'danger')
        return redirect(url_for('select_framework', scan_id=scan_id))
    
    # Generate the compliance report
    report = generate_compliance_report(scan_id, framework_id)
    if not report:
        flash('Failed to generate compliance report', 'danger')
        return redirect(url_for('select_framework', scan_id=scan_id))
    
    # Get detailed results from the report
    detailed_results = report.get_detailed_results()
    
    return render_template(
        'compliance.html', 
        scan=scan, 
        framework=framework_details, 
        report=report,
        detailed_results=detailed_results
    )


@app.route('/export-compliance/<int:scan_id>/<int:framework_id>/<format>')
@login_required
def export_compliance_report(scan_id, framework_id, format):
    """Export a compliance report in the specified format"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure the scan belongs to the current user
    if scan.user_id != current_user.id:
        flash('You do not have permission to export this report', 'danger')
        return redirect(url_for('dashboard'))
    
    # Only PDF is supported for now
    if format != 'pdf':
        flash('Only PDF format is supported for compliance reports at this time', 'warning')
        return redirect(url_for('compliance_report', scan_id=scan_id, framework_id=framework_id))
    
    # Generate the compliance report if it doesn't exist
    report = ComplianceReport.query.filter_by(scan_id=scan_id, framework_id=framework_id).first()
    if not report:
        report = generate_compliance_report(scan_id, framework_id)
        if not report:
            flash('Failed to generate compliance report', 'danger')
            return redirect(url_for('compliance_report', scan_id=scan_id, framework_id=framework_id))
    
    # Get framework details
    framework = get_framework_details(framework_id)
    if not framework:
        flash('Invalid framework selected', 'danger')
        return redirect(url_for('select_framework', scan_id=scan_id))
    
    # Get detailed results
    detailed_results = report.get_detailed_results()
    
    # Generate PDF report
    # For simplicity, we'll reuse the regular PDF report generator
    # but this would typically be extended with compliance-specific formatting
    pdf_path = generate_pdf_report(
        scan, 
        scan.results.all(),
        compliance_data={
            'framework': framework,
            'report': report,
            'detailed_results': detailed_results
        }
    )
    
    filename = f'compliance_report_{scan_id}_{framework["name"]}.pdf'
    return send_file(pdf_path, as_attachment=True, download_name=filename)


@app.route('/kali-toolkit')
@login_required
def kali_toolkit():
    """Page that displays Kali Linux toolkit for red/blue team operations"""
    return render_template('kali_toolkit.html')
