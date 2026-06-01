import 'package:flutter/material.dart';
import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:go_router/go_router.dart';

void main() {
  runApp(const GuardApp());
}

final router = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/results/:scanId',
      builder: (context, state) {
        final scanId = state.pathParameters['scanId']!;
        return ResultsPage(scanId: scanId);
      },
    ),
  ],
  errorBuilder: (contezt, state) =>
      Scaffold(body: Center(child: Text(state.error.toString()))),
);

class GuardApp extends StatelessWidget {
  const GuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      routerConfig: router,

      title: 'Guard',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
      ),
    );
  }
}

class ResultsPage extends StatefulWidget {
  final String scanId;
  const ResultsPage({super.key, required this.scanId});

  @override
  State<ResultsPage> createState() => _ResultsPageState();
}

class Finding {
  final String vulnType;
  final String lineNo;
  final String snippet;
  final String severity;

  Finding({
    required this.vulnType,
    required this.lineNo,
    required this.snippet,
    required this.severity,
  });

  factory Finding.fromJson(Map<String, dynamic> json) {
    return Finding(
      vulnType: json['vuln_type'],
      lineNo: json['line_no'],
      snippet: json['snippet'],
      severity: json['severity'],
    );
  }
}

class _ResultsPageState extends State<ResultsPage> {
  List<Finding> findings = [];
  bool isLoading = true;
  String scanId = '';
  Timer? pollingTimer;

  @override
  void initState() {
    super.initState();
    scanId = widget.scanId;
    startPolling();
  }

  @override
  void dispose() {
    pollingTimer?.cancel();
    super.dispose();
  }

  void startPolling() {
    pollingTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => fetchResults(),
    );
    fetchResults();
  }

  Future<void> fetchResults() async {
    final response = await http.get(
      Uri.parse('http://localhost:3000/api/results/$scanId'),
    );

    if (response.statusCode == 200) {
      setState(() {
        findings = (jsonDecode(response.body) as List)
            .map((f) => Finding.fromJson(f))
            .toList();
        isLoading = false;
      });
      pollingTimer?.cancel(); // stop polling
    }
    // if 404 keep polling
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1E1E2E),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E1E2E),
        title: const Text('Guard', style: TextStyle(color: Colors.white)),
      ),
      body: isLoading ? _buildLoading() : _buildResults(),
    );
  }

  Widget _buildLoading() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(color: Colors.purple),
          SizedBox(height: 16),
          Text('Scanning...', style: TextStyle(color: Colors.white)),
        ],
      ),
    );
  }

  Widget _buildResults() {
    final critical = findings.where((f) => f.severity == 'Critical').toList();
    final high = findings.where((f) => f.severity == 'High').toList();
    final medium = findings.where((f) => f.severity == 'Medium').toList();
    final low = findings.where((f) => f.severity == 'Low').toList();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSummary(critical, high, medium, low),
          const SizedBox(height: 24),
          if (critical.isNotEmpty)
            _buildSection('Critical', critical, Colors.red),
          if (high.isNotEmpty) _buildSection('High', high, Colors.orange),
          if (medium.isNotEmpty) _buildSection('Medium', medium, Colors.yellow),
          if (low.isNotEmpty) _buildSection('Low', low, Colors.green),
        ],
      ),
    );
  }

  Widget _buildSummary(
    List<Finding> critical,
    List<Finding> high,
    List<Finding> medium,
    List<Finding> low,
  ) {
    return Row(
      children: [
        Expanded(
          child: _buildSummaryCard('Critical', critical.length, Colors.red),
        ),
        const SizedBox(width: 8),
        Expanded(child: _buildSummaryCard('High', high.length, Colors.orange)),
        const SizedBox(width: 8),
        Expanded(
          child: _buildSummaryCard('Medium', medium.length, Colors.yellow),
        ),
        const SizedBox(width: 8),
        Expanded(child: _buildSummaryCard('Low', low.length, Colors.green)),
      ],
    );
  }

  Widget _buildSummaryCard(String label, int count, Color color) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        children: [
          Text(
            count.toString(),
            style: TextStyle(
              color: color,
              fontSize: 24,
              fontWeight: FontWeight.bold,
            ),
          ),
          Text(label, style: TextStyle(color: color)),
        ],
      ),
    );
  }

  Widget _buildSection(String title, List<Finding> findings, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: TextStyle(
            color: color,
            fontSize: 18,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        ...findings.map((f) => _buildFindingCard(f, color)),
        const SizedBox(height: 24),
      ],
    );
  }

  Widget _buildFindingCard(Finding finding, Color color) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF2E2E3E),
        borderRadius: BorderRadius.circular(8),
        border: Border(left: BorderSide(color: color, width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            finding.vulnType,
            style: const TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Line ${finding.lineNo}',
            style: const TextStyle(color: Colors.grey),
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E2E),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              finding.snippet,
              style: const TextStyle(
                color: Colors.white70,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }
}
