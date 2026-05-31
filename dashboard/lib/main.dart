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
  errorBuilder: (contezt, state) => Scaffold(
    body: Center(child: Text(state.error.toString())),
  ),
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

class _ResultsPageState extends State<ResultsPage> {
  List<dynamic> findings = [];
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
        findings = jsonDecode(response.body);
        isLoading = false;
      });
      pollingTimer?.cancel(); // stop polling
    }
    // if 404 keep polling
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Guard - Scan Results')),
      body: isLoading
    ? const Center(child: CircularProgressIndicator())
    : ListView.builder(
        itemCount: findings.length,
        itemBuilder: (context, index) {
          return ListTile(
            title: Text(findings[index].toString()),
          );
        },
      ),
    );
  }
}
