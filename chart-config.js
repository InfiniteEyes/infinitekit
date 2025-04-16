/**
 * Chart configuration and utility functions for C2 System
 */

/**
 * Create a doughnut chart with customized options
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Chart data (labels and datasets)
 */
function createDoughnutChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    const chart = new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8f9fa',
                        padding: 10
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(33, 37, 41, 0.9)'
                }
            },
            cutout: '65%'
        }
    });
}

/**
 * Create a bar chart with customized options
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Chart data (labels and datasets)
 */
function createBarChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Add backgroundColor and hoverBackgroundColor to dataset if not present
    if (data.datasets && data.datasets.length > 0) {
        data.datasets.forEach(dataset => {
            if (!dataset.backgroundColor) {
                dataset.backgroundColor = '#0d6efd';
            }
            if (!dataset.hoverBackgroundColor) {
                dataset.hoverBackgroundColor = '#0a58ca';
            }
        });
    }
    
    const chart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(33, 37, 41, 0.9)'
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#f8f9fa'
                    },
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#f8f9fa',
                        precision: 0
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}

/**
 * Create a horizontal bar chart
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Chart data (labels and datasets)
 */
function createHorizontalBarChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    const chart = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(33, 37, 41, 0.9)'
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color: '#f8f9fa',
                        precision: 0
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#f8f9fa'
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

/**
 * Create a line chart
 * @param {string} elementId - Canvas element ID
 * @param {Object} data - Chart data (labels and datasets)
 */
function createLineChart(elementId, data) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    // Ensure datasets have proper styling
    if (data.datasets && data.datasets.length > 0) {
        data.datasets.forEach(dataset => {
            if (!dataset.borderColor) {
                dataset.borderColor = '#0d6efd';
            }
            dataset.tension = 0.3;
            dataset.borderWidth = 2;
        });
    }
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    backgroundColor: 'rgba(33, 37, 41, 0.9)'
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#f8f9fa'
                    },
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#f8f9fa'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        }
    });
}
