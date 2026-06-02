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

class FinalFinding {
  final String fileName;
  final List<Finding> findings;

  FinalFinding({required this.fileName, required this.findings});

  factory FinalFinding.fromJson(Map<String, dynamic> json) {
    return FinalFinding(
      fileName: json['file_name'],
      findings: (json['findings'] as List)
          .map((f) => Finding.fromJson(f))
          .toList(),
    );
  }
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
  List<FinalFinding> findings = [];
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
      final List<dynamic> data = jsonDecode(response.body);

      setState(() {
        findings = data.map((e) => FinalFinding.fromJson(e)).toList();
        isLoading = false;
        ;
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
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [...findings.map((f) => _buildFileSection(f))],
      ),
    );
  }

  Widget _buildFileSection(FinalFinding fileResult) {
    return Container(
      margin: const EdgeInsets.only(bottom: 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // filename header
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF2E2E3E),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              fileResult.fileName,
              style: const TextStyle(
                color: Colors.white,
                fontFamily: 'monospace',
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          const SizedBox(height: 8),
          // findings under this file
          ...fileResult.findings.map((f) => _buildFindingCard(f)),
        ],
      ),
    );
  }

  Widget _buildFindingCard(Finding finding) {
    final color = switch (finding.severity) {
      'Critical' => Colors.red,
      'High' => Colors.orange,
      'Medium' => Colors.yellow,
      'Low' => Colors.green,
      _ => Colors.grey,
    };
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
