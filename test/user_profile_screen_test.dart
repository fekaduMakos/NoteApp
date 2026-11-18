import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cloud_notes_fresh/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await AuthService.instance.initialize();
    await AuthService.instance.register(
      name: 'John Doe',
      email: 'john@example.com',
      password: 'Password123',
    );
  });

  testWidgets('UserProfileScreen renders personal info tab and security tab', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: UserProfileScreen(),
      ),
    );
    await tester.pumpAndSettle();

    // Verify Title and Tabs
    expect(find.text('Edit Profile & Account'), findsOneWidget);
    expect(find.text('Personal Info'), findsOneWidget);
    expect(find.text('Security & Login'), findsOneWidget);

    // Verify Personal Info Fields
    expect(find.text('John Doe'), findsWidgets);
    expect(find.text('john@example.com'), findsWidgets);
    expect(find.text('Full Name *'), findsOneWidget);
    expect(find.text('Email Address *'), findsOneWidget);
    expect(find.text('Save Profile Changes'), findsOneWidget);

    // Switch to Security & Login Tab
    await tester.tap(find.text('Security & Login'));
    await tester.pumpAndSettle();

    // Verify Security Elements
    expect(find.text('Change Account Password'), findsOneWidget);
    expect(find.text('Current Password *'), findsOneWidget);
    expect(find.text('New Password *'), findsOneWidget);
    expect(find.text('Confirm New Password *'), findsOneWidget);
    expect(find.text('Update Password'), findsOneWidget);
    expect(find.text('Security PIN Lock'), findsOneWidget);
    expect(find.text('Log Out of Account'), findsOneWidget);
  });
}
