import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:cloud_notes_fresh/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await AuthService.instance.initialize();
  });

  group('User Profile & Personal Info Tests', () {
    test('Can register user, update profile name, email, phone, bio and avatar color', () async {
      // 1. Register a user
      final user = await AuthService.instance.register(
        name: 'Initial Name',
        email: 'user@example.com',
        password: 'Password123',
      );

      expect(user.name, equals('Initial Name'));
      expect(user.email, equals('user@example.com'));
      expect(user.phone, isNull);
      expect(user.bio, isNull);

      // 2. Update profile information
      final updated = await AuthService.instance.updateProfile(
        name: 'Updated Name',
        email: 'newemail@example.com',
        phone: '+1 555 123 4567',
        bio: 'Senior Software Engineer & Note Taker',
        avatarColor: 0xFF00897B, // Teal
      );

      expect(updated.name, equals('Updated Name'));
      expect(updated.email, equals('newemail@example.com'));
      expect(updated.phone, equals('+1 555 123 4567'));
      expect(updated.bio, equals('Senior Software Engineer & Note Taker'));
      expect(updated.avatarColor, equals(0xFF00897B));

      // 3. Verify currentUser in AuthService is immediately updated
      final current = AuthService.instance.currentUser;
      expect(current?.name, equals('Updated Name'));
      expect(current?.email, equals('newemail@example.com'));
      expect(current?.phone, equals('+1 555 123 4567'));
      expect(current?.bio, equals('Senior Software Engineer & Note Taker'));
      expect(current?.avatarColor, equals(0xFF00897B));
    });

    test('Prevents updating to an invalid email format', () async {
      await AuthService.instance.register(
        name: 'Test User',
        email: 'valid@example.com',
        password: 'Password123',
      );

      expect(
        () => AuthService.instance.updateProfile(
          name: 'Test User',
          email: 'invalid-email-address',
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('Prevents updating to an empty name', () async {
      await AuthService.instance.register(
        name: 'Test User',
        email: 'valid@example.com',
        password: 'Password123',
      );

      expect(
        () => AuthService.instance.updateProfile(
          name: '   ',
          email: 'valid@example.com',
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('Prevents updating email to an existing email taken by another user', () async {
      // Register user 1
      await AuthService.instance.register(
        name: 'User One',
        email: 'one@example.com',
        password: 'Password123',
      );

      // Register user 2 (this also sets session to user 2)
      await AuthService.instance.register(
        name: 'User Two',
        email: 'two@example.com',
        password: 'Password123',
      );

      // Attempt to update User Two's email to User One's email
      expect(
        () => AuthService.instance.updateProfile(
          name: 'User Two',
          email: 'one@example.com',
        ),
        throwsA(predicate((e) => e.toString().contains('already exists'))),
      );
    });

    test('Securely changes password with current password verification', () async {
      await AuthService.instance.register(
        name: 'Password Test',
        email: 'pwd@example.com',
        password: 'InitialPassword1',
      );

      // Wrong current password fails
      expect(
        () => AuthService.instance.changePassword(
          currentPassword: 'WrongPassword',
          newPassword: 'BrandNewPassword1',
        ),
        throwsA(predicate((e) => e.toString().contains('Current password is incorrect'))),
      );

      // Successfully change password
      await AuthService.instance.changePassword(
        currentPassword: 'InitialPassword1',
        newPassword: 'BrandNewPassword1',
      );

      // Verify that the new password allows login
      await AuthService.instance.logout();
      final loggedIn = await AuthService.instance.login(
        email: 'pwd@example.com',
        password: 'BrandNewPassword1',
      );
      expect(loggedIn.email, equals('pwd@example.com'));

      // Old password no longer works
      await AuthService.instance.logout();
      expect(
        () => AuthService.instance.login(
          email: 'pwd@example.com',
          password: 'InitialPassword1',
        ),
        throwsA(isA<Exception>()),
      );
    });
  });
}
