#!/bin/bash

# Detector Project - Automated Demo Script
# This script demonstrates all key features of the system

set -e

echo "🚀 Detector Project - Live Demonstration"
echo "========================================"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if services are running
check_services() {
    print_status "Checking service status..."

    if curl -s http://localhost:9200/_cluster/health > /dev/null; then
        print_success "Elasticsearch is running"
    else
        print_warning "Elasticsearch not accessible at localhost:9200"
    fi

    if curl -s http://localhost:5601/api/status > /dev/null; then
        print_success "Kibana is running"
    else
        print_warning "Kibana not accessible at localhost:5601"
    fi
}

# Process sample logs
process_sample_logs() {
    print_status "Processing sample logs through parser..."

    cd parser

    # Process each sample log file
    echo "📊 Processing syslog samples..."
    python src/parser.py --file ../logs/sample-syslog.log --host localhost --port 9200

    echo "📋 Processing JSON logs..."
    python src/parser.py --file ../logs/sample-json.log --host localhost --port 9200

    echo "📈 Processing CSV logs..."
    python src/parser.py --file ../logs/sample.csv --host localhost --port 9200

    cd ..
    print_success "Sample logs processed successfully"
}

# Run advanced detection algorithms
run_detection_demo() {
    print_status "Running advanced ML detection algorithms..."

    cd rules/engine

    # Run the advanced detection demo
    python advanced_detection.py

    cd ../..
    print_success "Detection algorithms completed"
}

# Test alerting system
test_alerting() {
    print_status "Testing alerting system..."

    cd alerts

    # Run alert manager (will show available channels)
    python alert_manager.py

    cd ..
    print_success "Alert system tested"
}

# Show Kibana information
show_kibana_info() {
    print_status "Kibana Dashboard Information:"
    echo "🌐 Access Kibana at: http://localhost:5601"
    echo ""
    echo "📊 Setup Steps:"
    echo "1. Go to http://localhost:5601"
    echo "2. Click 'Explore on my own'"
    echo "3. Create index pattern: 'detector-logs-*'"
    echo "4. Go to 'Discover' to see processed logs"
    echo "5. Import dashboard from: dashboards/security-overview.json"
    echo ""
    print_success "Kibana ready for exploration"
}

# Main demo flow
main() {
    echo ""
    print_status "Starting comprehensive demo..."

    # Check services
    check_services

    echo ""
    print_status "Step 1: Processing sample logs..."
    process_sample_logs

    echo ""
    print_status "Step 2: Running ML detection algorithms..."
    run_detection_demo

    echo ""
    print_status "Step 3: Testing alerting capabilities..."
    test_alerting

    echo ""
    print_status "Step 4: Kibana dashboard setup..."
    show_kibana_info

    echo ""
    echo "🎉 DEMO COMPLETE!"
    echo "==============="
    print_success "Detector system fully demonstrated!"
    echo ""
    echo "📋 Project Highlights:"
    echo "• ✅ Multi-format log parsing (7 formats supported)"
    echo "• ✅ ML-based anomaly detection"
    echo "• ✅ Behavioral analysis engine"
    echo "• ✅ Real-time threat detection"
    echo "• ✅ Multi-channel alerting system"
    echo "• ✅ Production-ready architecture"
    echo "• ✅ Comprehensive testing & CI/CD"
    echo ""
    echo "🔗 Next Steps:"
    echo "• Deploy to production with: railway up"
    echo "• Access live demo at your deployment URL"
    echo "• Customize detection rules in rules/samples/"
    echo "• Add your own log sources for testing"
}

# Handle command line arguments
case "${1:-}" in
    "services")
        check_services
        ;;
    "logs")
        process_sample_logs
        ;;
    "detection")
        run_detection_demo
        ;;
    "alerts")
        test_alerting
        ;;
    "kibana")
        show_kibana_info
        ;;
    "full"|"")
        main
        ;;
    *)
        echo "Usage: $0 [services|logs|detection|alerts|kibana|full]"
        echo "  services  - Check service status"
        echo "  logs      - Process sample logs only"
        echo "  detection - Run detection algorithms only"
        echo "  alerts    - Test alerting system only"
        echo "  kibana    - Show Kibana setup info only"
        echo "  full      - Run complete demo (default)"
        exit 1
esac
