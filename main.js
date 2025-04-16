/**
 * Main JavaScript functionality for the C2 System
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))
    
    // Initialize popovers
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]')
    const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl))
    
    // Function to check status of running scans
    function checkScansStatus() {
        // Look for elements with data-scan-id attribute
        const scanElements = document.querySelectorAll('[data-scan-id]');
        
        scanElements.forEach(element => {
            const scanId = element.getAttribute('data-scan-id');
            const statusElement = element.querySelector('.scan-status');
            
            if (statusElement && (statusElement.textContent.trim() === 'Pending' || statusElement.textContent.trim() === 'In Progress')) {
                fetch(`/scan-status/${scanId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'completed' || data.status === 'failed') {
                            // Refresh the page to show updated status
                            window.location.reload();
                        }
                    })
                    .catch(error => console.error('Error checking scan status:', error));
            }
        });
    }
    
    // Set interval to check for scan status updates every 5 seconds
    const scanStatusInterval = setInterval(checkScansStatus, 5000);
    
    // Disable form submission buttons on submit to prevent double-submission
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                const originalText = submitButton.innerHTML;
                submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
                
                // Re-enable after 10 seconds in case of errors
                setTimeout(() => {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }, 10000);
            }
        });
    });
    
    // Handle confirmation dialogs
    const confirmButtons = document.querySelectorAll('[data-confirm]');
    confirmButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm') || 'Are you sure you want to perform this action?';
            if (!confirm(message)) {
                e.preventDefault();
                return false;
            }
        });
    });
});
