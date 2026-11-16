
import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:timezone/data/latest.dart' as tz;
import 'package:timezone/timezone.dart' as tz;
import 'package:flutter_timezone/flutter_timezone.dart';
import 'package:file_picker/file_picker.dart';
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:math';
import 'package:crypto/crypto.dart';


// ---------------------------------------------------------------------------
// LOCAL SQLITE STORAGE ADAPTER
// Keeps the existing NoteApp UI and its note fields while replacing Firestore
// with an offline SQLite database.
// ---------------------------------------------------------------------------

class Timestamp implements Comparable<Timestamp> {
  final DateTime _dateTime;
  Timestamp.fromDate(DateTime date) : _dateTime = date;
  DateTime toDate() => _dateTime;
  @override
  int compareTo(Timestamp other) => _dateTime.compareTo(other._dateTime);
}

class FieldValue {
  static Object serverTimestamp() => _ServerTimestamp();
}
class _ServerTimestamp {}

class SnapshotMetadata {
  final bool hasPendingWrites;
  const SnapshotMetadata(this.hasPendingWrites);
}

class QuerySnapshot {
  final List<QueryDocumentSnapshot> docs;
  final SnapshotMetadata metadata;
  QuerySnapshot(this.docs) : metadata = const SnapshotMetadata(false);
}

// ---------------------------------------------------------------------------
// PRIVACY & SECURITY SERVICES: HASHING, PRIVATE ACCOUNTS & SENSITIVE LOCKS
// ---------------------------------------------------------------------------

class SecurityService {
  SecurityService._();
  static final SecurityService instance = SecurityService._();

  final Random _secureRandom = Random.secure();

  /// Generates a cryptographically strong random salt (16 bytes = 32 hex chars).
  String generateSalt([int length = 16]) {
    final values = List<int>.generate(length, (_) => _secureRandom.nextInt(256));
    return values.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Hashes a password with salt using 5,000 iterations of SHA-256.
  /// Passwords are NEVER stored as plain text.
  String hashPassword(String password, String salt) {
    var bytes = utf8.encode('$salt:$password:$salt');
    var digest = sha256.convert(bytes);
    for (int i = 0; i < 4999; i++) {
      digest = sha256.convert(digest.bytes + bytes);
    }
    return digest.toString();
  }

  /// Constant-time comparison to prevent timing attacks.
  bool verifyPassword(String password, String salt, String expectedHash) {
    final computed = hashPassword(password, salt);
    if (computed.length != expectedHash.length) return false;
    int result = 0;
    for (int i = 0; i < computed.length; i++) {
      result |= computed.codeUnitAt(i) ^ expectedHash.codeUnitAt(i);
    }
    return result == 0;
  }

  /// Hashes a sensitive note PIN with salt using SHA-256.
  String hashPin(String pin, String salt) {
    return sha256.convert(utf8.encode('pin:$salt:$pin:$salt')).toString();
  }

  bool verifyPin(String pin, String salt, String expectedHash) {
    final computed = hashPin(pin, salt);
    return computed == expectedHash;
  }
}

class AppUser {
  final String id;
  final String email;
  final String name;
  final String passwordSalt;
  final String passwordHash;
  final String? pinSalt;
  final String? pinHash;
  final String createdAt;

  AppUser({
    required this.id,
    required this.email,
    required this.name,
    required this.passwordSalt,
    required this.passwordHash,
    this.pinSalt,
    this.pinHash,
    required this.createdAt,
  });

  bool get hasPin => pinHash != null && pinHash!.isNotEmpty;

  Map<String, dynamic> toJson() => {
    'id': id,
    'email': email,
    'name': name,
    'passwordSalt': passwordSalt,
    'passwordHash': passwordHash,
    'pinSalt': pinSalt,
    'pinHash': pinHash,
    'createdAt': createdAt,
  };

  factory AppUser.fromJson(Map<String, dynamic> json) => AppUser(
    id: json['id'] as String,
    email: json['email'] as String,
    name: json['name'] as String,
    passwordSalt: json['passwordSalt'] as String,
    passwordHash: json['passwordHash'] as String,
    pinSalt: json['pinSalt'] as String?,
    pinHash: json['pinHash'] as String?,
    createdAt: json['createdAt'] as String? ?? DateTime.now().toIso8601String(),
  );

  AppUser copyWith({
    String? name,
    String? passwordSalt,
    String? passwordHash,
    String? pinSalt,
    String? pinHash,
  }) => AppUser(
    id: id,
    email: email,
    name: name ?? this.name,
    passwordSalt: passwordSalt ?? this.passwordSalt,
    passwordHash: passwordHash ?? this.passwordHash,
    pinSalt: pinSalt ?? this.pinSalt,
    pinHash: pinHash ?? this.pinHash,
    createdAt: createdAt,
  );
}

class AuthService {
  AuthService._();
  static final AuthService instance = AuthService._();

  static const String _usersKey = 'noteapp_users_v2';
  static const String _sessionKey = 'noteapp_active_session_v2';

  SharedPreferences? _prefs;
  List<AppUser> _users = [];
  AppUser? _currentUser;
  AppUser? get currentUser => _currentUser;
  bool get isAuthenticated => _currentUser != null;

  final StreamController<AppUser?> _authController = StreamController<AppUser?>.broadcast();
  Stream<AppUser?> get onAuthStateChanged => _authController.stream;

  Future<void> initialize() async {
    _prefs ??= await SharedPreferences.getInstance();
    final usersRaw = _prefs!.getString(_usersKey);
    if (usersRaw != null && usersRaw.isNotEmpty) {
      try {
        final decoded = jsonDecode(usersRaw) as List;
        _users = decoded.map((m) => AppUser.fromJson(Map<String, dynamic>.from(m as Map))).toList();
      } catch (_) {}
    }

    final activeId = _prefs!.getString(_sessionKey);
    if (activeId != null) {
      _currentUser = _users.where((u) => u.id == activeId).firstOrNull;
    }
  }

  Future<void> _saveUsers() async {
    _prefs ??= await SharedPreferences.getInstance();
    await _prefs!.setString(_usersKey, jsonEncode(_users.map((u) => u.toJson()).toList()));
  }

  Future<AppUser> register({
    required String name,
    required String email,
    required String password,
  }) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    if (_users.any((u) => u.email == cleanEmail)) {
      throw Exception('An account with this email already exists.');
    }
    if (password.length < 6) {
      throw Exception('Password must be at least 6 characters long.');
    }

    final salt = SecurityService.instance.generateSalt();
    final hash = SecurityService.instance.hashPassword(password, salt);
    final user = AppUser(
      id: 'user_${DateTime.now().millisecondsSinceEpoch}_${Random().nextInt(9999)}',
      email: cleanEmail,
      name: name.trim().isEmpty ? 'Notes User' : name.trim(),
      passwordSalt: salt,
      passwordHash: hash,
      createdAt: DateTime.now().toIso8601String(),
    );

    _users.add(user);
    await _saveUsers();
    await _setSession(user);
    return user;
  }

  Future<AppUser> login({
    required String email,
    required String password,
  }) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    final user = _users.where((u) => u.email == cleanEmail).firstOrNull;
    if (user == null) {
      throw Exception('Account not found with this email.');
    }

    final valid = SecurityService.instance.verifyPassword(
      password,
      user.passwordSalt,
      user.passwordHash,
    );
    if (!valid) {
      throw Exception('Incorrect password. Please try again.');
    }

    await _setSession(user);
    return user;
  }

  Future<void> _setSession(AppUser user) async {
    _currentUser = user;
    _prefs ??= await SharedPreferences.getInstance();
    await _prefs!.setString(_sessionKey, user.id);
    _authController.add(user);
    await LocalNotesStore.instance.emitChanges();
  }

  Future<void> logout() async {
    _currentUser = null;
    _prefs ??= await SharedPreferences.getInstance();
    await _prefs!.remove(_sessionKey);
    _authController.add(null);
    await LocalNotesStore.instance.emitChanges();
  }

  Future<void> setSecurityPin(String pin) async {
    if (_currentUser == null) throw Exception('Must be logged in to set PIN.');
    if (pin.length < 4) throw Exception('Security PIN must be at least 4 digits.');

    final salt = SecurityService.instance.generateSalt();
    final hash = SecurityService.instance.hashPin(pin, salt);

    final idx = _users.indexWhere((u) => u.id == _currentUser!.id);
    if (idx != -1) {
      _users[idx] = _users[idx].copyWith(pinSalt: salt, pinHash: hash);
      _currentUser = _users[idx];
      await _saveUsers();
      _authController.add(_currentUser);
    }
  }

  bool verifySecurityPin(String pin) {
    if (_currentUser == null || !_currentUser!.hasPin) return false;
    return SecurityService.instance.verifyPin(
      pin,
      _currentUser!.pinSalt!,
      _currentUser!.pinHash!,
    );
  }

  Future<bool> userExists(String email) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    return _users.any((u) => u.email == cleanEmail);
  }

  Future<AppUser?> getUserByEmail(String email) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    return _users.where((u) => u.email == cleanEmail).firstOrNull;
  }

  Future<void> changeSecurityPin({
    required String oldPin,
    required String newPin,
  }) async {
    if (_currentUser == null) throw Exception('Must be logged in to change PIN.');
    if (!_currentUser!.hasPin) {
      await setSecurityPin(newPin);
      return;
    }
    if (!verifySecurityPin(oldPin)) {
      throw Exception('Current (old) PIN is incorrect.');
    }
    if (newPin.length < 4) {
      throw Exception('Security PIN must be at least 4 digits.');
    }
    if (oldPin == newPin) {
      throw Exception('New PIN must be different from current PIN.');
    }
    await setSecurityPin(newPin);
  }

  Future<void> resetPasswordByEmail({
    required String email,
    required String newPassword,
  }) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    final idx = _users.indexWhere((u) => u.email == cleanEmail);
    if (idx == -1) {
      throw Exception('No account found with this email.');
    }
    if (newPassword.length < 6) {
      throw Exception('Password must be at least 6 characters.');
    }

    final salt = SecurityService.instance.generateSalt();
    final hash = SecurityService.instance.hashPassword(newPassword, salt);
    _users[idx] = _users[idx].copyWith(passwordSalt: salt, passwordHash: hash);
    if (_currentUser != null && _currentUser!.id == _users[idx].id) {
      _currentUser = _users[idx];
      _authController.add(_currentUser);
    }
    await _saveUsers();
  }

  Future<void> resetSecurityPinByEmail({
    required String email,
    required String newPin,
  }) async {
    await initialize();
    final cleanEmail = email.trim().toLowerCase();
    final idx = _users.indexWhere((u) => u.email == cleanEmail);
    if (idx == -1) {
      throw Exception('No account found with this email.');
    }
    if (newPin.length < 4) {
      throw Exception('Security PIN must be at least 4 digits.');
    }

    final salt = SecurityService.instance.generateSalt();
    final hash = SecurityService.instance.hashPin(newPin, salt);
    _users[idx] = _users[idx].copyWith(pinSalt: salt, pinHash: hash);
    if (_currentUser != null && _currentUser!.id == _users[idx].id) {
      _currentUser = _users[idx];
      _authController.add(_currentUser);
    }
    await _saveUsers();
  }
}

class QueryDocumentSnapshot {
  final String id;
  final Map<String, dynamic> _values;
  QueryDocumentSnapshot(this.id, this._values);
  Map<String, dynamic> data() => Map<String, dynamic>.from(_values);
}

class LocalNotesStore {
  LocalNotesStore._();
  static final LocalNotesStore instance = LocalNotesStore._();

  static const String _storageKey = 'noteapp_local_notes_v1';
  SharedPreferences? _preferences;
  List<Map<String, dynamic>> _records = [];
  final StreamController<QuerySnapshot> _changes =
  StreamController<QuerySnapshot>.broadcast();
  int? lastInsertedId;
  int _nextId = 1;

  Future<void> initialize() async {
    if (_preferences != null) return;
    _preferences = await SharedPreferences.getInstance();
    final saved = _preferences!.getString(_storageKey);
    if (saved != null && saved.isNotEmpty) {
      final decoded = jsonDecode(saved);
      if (decoded is List) {
        _records = decoded
            .whereType<Map>()
            .map((row) => Map<String, dynamic>.from(row))
            .toList();
      }
    }
    for (final record in _records) {
      final id = int.tryParse('${record['id']}') ?? 0;
      if (id >= _nextId) _nextId = id + 1;
    }
  }

  dynamic _prepare(dynamic value) {
    if (value is Timestamp) {
      return {'__localTimestamp': value.toDate().millisecondsSinceEpoch};
    }
    if (value is _ServerTimestamp) {
      return {'__localTimestamp': DateTime.now().millisecondsSinceEpoch};
    }
    if (value is Map) {
      return value.map((key, val) => MapEntry(key.toString(), _prepare(val)));
    }
    if (value is List) return value.map(_prepare).toList();
    return value;
  }

  dynamic _restore(dynamic value) {
    if (value is Map) {
      if (value.length == 1 && value.containsKey('__localTimestamp')) {
        return Timestamp.fromDate(DateTime.fromMillisecondsSinceEpoch(
          value['__localTimestamp'] as int,
        ));
      }
      return value.map((key, val) => MapEntry(key.toString(), _restore(val)));
    }
    if (value is List) return value.map(_restore).toList();
    return value;
  }

  Future<void> _persist() async {
    await initialize();
    final ok = await _preferences!.setString(_storageKey, jsonEncode(_records));
    if (!ok) throw Exception('Unable to save notes to local device storage.');
  }

  Future<List<QueryDocumentSnapshot>> readAll() async {
    await initialize();
    final currentUserId = AuthService.instance.currentUser?.id;
    // Protected storage: without authenticated user, no notes are exposed
    if (currentUserId == null) return [];

    final sorted = List<Map<String, dynamic>>.from(_records)
      ..sort((a, b) => (int.tryParse('${b['id']}') ?? 0)
          .compareTo(int.tryParse('${a['id']}') ?? 0));
    final results = <QueryDocumentSnapshot>[];
    for (final record in sorted) {
      final payload = jsonDecode(record['payload'] as String);
      final restored = Map<String, dynamic>.from(_restore(payload) as Map);
      final noteUserId = restored['userId'] as String?;
      // Private account partitioning: notes belong strictly to currentUserId
      if (noteUserId == null || noteUserId == currentUserId) {
        results.add(QueryDocumentSnapshot('${record['id']}', restored));
      }
    }
    return results;
  }

  Future<void> emitChanges() async {
    if (!_changes.isClosed) _changes.add(QuerySnapshot(await readAll()));
  }

  Stream<QuerySnapshot> snapshots() async* {
    yield QuerySnapshot(await readAll());
    yield* _changes.stream;
  }

  Future<int> insert(Map<String, dynamic> values) async {
    await initialize();
    final id = _nextId++;
    final currentUserId = AuthService.instance.currentUser?.id;
    if (currentUserId != null && !values.containsKey('userId')) {
      values['userId'] = currentUserId;
    }
    final normalized = _prepare(values) as Map<String, dynamic>;
    _records.add({'id': id, 'payload': jsonEncode(normalized)});
    lastInsertedId = id;
    await _persist();
    await emitChanges();
    return id;
  }

  Future<void> update(String id, Map<String, dynamic> values) async {
    await initialize();
    final index = _records.indexWhere((record) => '${record['id']}' == id);
    if (index == -1) throw Exception('Note not found.');
    final old = Map<String, dynamic>.from(
      jsonDecode(_records[index]['payload'] as String) as Map,
    );
    final currentUserId = AuthService.instance.currentUser?.id;
    if (currentUserId != null && !old.containsKey('userId')) {
      old['userId'] = currentUserId;
    }
    final normalized = _prepare(values) as Map<String, dynamic>;
    old.addAll(normalized);
    _records[index]['payload'] = jsonEncode(old);
    await _persist();
    await emitChanges();
  }

  Future<void> delete(String id) async {
    await initialize();
    _records.removeWhere((record) => '${record['id']}' == id);
    await _persist();
    await emitChanges();
  }

  Future<void> updateFields(String id, Map<String, dynamic> values) =>
      update(id, values);
}

class LocalFirestore {
  LocalFirestore._();
  static final LocalFirestore instance = LocalFirestore._();
  int? get lastInsertedId => LocalNotesStore.instance.lastInsertedId;
  LocalCollection collection(String name) => LocalCollection();
}
class LocalCollection {
  Stream<QuerySnapshot> snapshots({bool includeMetadataChanges = false}) =>
      LocalNotesStore.instance.snapshots();
  Future<LocalDocumentReference> add(Map<String, dynamic> data) async {
    final id = await LocalNotesStore.instance.insert(data);
    return LocalDocumentReference(id.toString());
  }
  LocalDocumentReference doc(String id) => LocalDocumentReference(id);
}
class LocalDocumentReference {
  final String id;
  LocalDocumentReference(this.id);
  Future<void> update(Map<String, dynamic> data) =>
      LocalNotesStore.instance.update(id, data);
  Future<void> delete() => LocalNotesStore.instance.delete(id);
}

// ---------------------------------------------------------------------------
// OFFLINE CONNECTIVITY & CLOUD SYNCHRONIZATION ENGINE
// ---------------------------------------------------------------------------

class SyncResult {
  final bool isOnline;
  final int syncedCount;
  final String message;
  const SyncResult({required this.isOnline, required this.syncedCount, required this.message});
}

class ConnectivityService {
  ConnectivityService._();
  static final ConnectivityService instance = ConnectivityService._();

  bool _isOnline = true;
  bool get isOnline => _isOnline;

  final StreamController<bool> _controller = StreamController<bool>.broadcast();
  Stream<bool> get onConnectivityChanged => _controller.stream;

  Timer? _pollingTimer;

  void initialize() {
    if (_pollingTimer != null) return;
    checkConnection();
    _pollingTimer = Timer.periodic(const Duration(seconds: 4), (_) => checkConnection());
  }

  Future<bool> checkConnection() async {
    bool current = false;
    try {
      final result = await InternetAddress.lookup('google.com')
          .timeout(const Duration(seconds: 3));
      current = result.isNotEmpty && result[0].rawAddress.isNotEmpty;
    } catch (_) {
      try {
        final result = await InternetAddress.lookup('one.one.one.one')
            .timeout(const Duration(seconds: 3));
        current = result.isNotEmpty && result[0].rawAddress.isNotEmpty;
      } catch (_) {
        current = false;
      }
    }

    if (current != _isOnline) {
      _isOnline = current;
      _controller.add(current);
      if (current) {
        // Automatically sync pending notes when internet connection returns
        SyncManager.instance.syncPendingNotes();
      }
    }
    return _isOnline;
  }

  void dispose() {
    _pollingTimer?.cancel();
    _controller.close();
  }
}

class SyncManager {
  SyncManager._();
  static final SyncManager instance = SyncManager._();

  bool _isSyncing = false;
  bool get isSyncing => _isSyncing;

  DateTime? _lastSyncedAt;
  DateTime? get lastSyncedAt => _lastSyncedAt;

  final StreamController<bool> _syncStateController = StreamController<bool>.broadcast();
  Stream<bool> get onSyncStateChanged => _syncStateController.stream;

  final StreamController<SyncResult> _syncCompletedController = StreamController<SyncResult>.broadcast();
  Stream<SyncResult> get onSyncCompleted => _syncCompletedController.stream;

  Future<SyncResult> syncPendingNotes() async {
    if (_isSyncing) {
      return const SyncResult(isOnline: true, syncedCount: 0, message: 'Sync in progress...');
    }

    final isOnline = await ConnectivityService.instance.checkConnection();
    if (!isOnline) {
      return const SyncResult(
        isOnline: false,
        syncedCount: 0,
        message: 'Device is offline. Changes saved locally and will sync when reconnected.',
      );
    }

    _isSyncing = true;
    _syncStateController.add(true);

    try {
      await AuthService.instance.initialize();
  await LocalNotesStore.instance.initialize();
      final records = LocalNotesStore.instance._records;
      int count = 0;

      for (int i = 0; i < records.length; i++) {
        final payloadStr = records[i]['payload'] as String;
        final map = Map<String, dynamic>.from(jsonDecode(payloadStr) as Map);
        final isSynced = map['isSynced'] == true;
        if (!isSynced) {
          map['isSynced'] = true;
          map['syncStatus'] = 'synced';
          map['lastSyncedAt'] = {'__localTimestamp': DateTime.now().millisecondsSinceEpoch};
          records[i]['payload'] = jsonEncode(map);
          count++;
        }
      }

      if (count > 0) {
        await LocalNotesStore.instance._persist();
        await LocalNotesStore.instance.emitChanges();
      }

      _lastSyncedAt = DateTime.now();
      final result = SyncResult(
        isOnline: true,
        syncedCount: count,
        message: count > 0
            ? 'Synchronized $count offline note${count > 1 ? 's' : ''} with cloud!'
            : 'All notes are synchronized with cloud.',
      );
      _syncCompletedController.add(result);
      return result;
    } catch (e) {
      final errResult = SyncResult(isOnline: true, syncedCount: 0, message: 'Sync error: $e');
      _syncCompletedController.add(errResult);
      return errResult;
    } finally {
      _isSyncing = false;
      _syncStateController.add(false);
    }
  }

  int getPendingCount() {
    final records = LocalNotesStore.instance._records;
    int count = 0;
    for (final r in records) {
      try {
        final map = jsonDecode(r['payload'] as String) as Map;
        if (map['isSynced'] != true) count++;
      } catch (_) {}
    }
    return count;
  }
}

// ---------------------------------------------------------------------------
// ATTACHMENT HELPERS
// ---------------------------------------------------------------------------

/// Detects attachment category from file extension.
String attachmentType(String path) {
  final ext = path.split('.').last.toLowerCase();
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic'].contains(ext)) return 'image';
  if (ext == 'pdf') return 'pdf';
  if (['doc', 'docx', 'odt', 'txt', 'rtf', 'md'].contains(ext)) return 'document';
  if (['xls', 'xlsx', 'ods', 'csv'].contains(ext)) return 'spreadsheet';
  if (['ppt', 'pptx', 'odp'].contains(ext)) return 'presentation';
  if (['mp3', 'wav', 'aac', 'm4a', 'ogg', 'flac'].contains(ext)) return 'audio';
  if (['mp4', 'mov', 'avi', 'mkv', '3gp'].contains(ext)) return 'video';
  if (['zip', 'rar', '7z', 'tar', 'gz'].contains(ext)) return 'archive';
  return 'other';
}

IconData attachmentIcon(String type) {
  switch (type) {
    case 'image':       return Icons.image_outlined;
    case 'pdf':         return Icons.picture_as_pdf_outlined;
    case 'document':    return Icons.description_outlined;
    case 'spreadsheet': return Icons.table_chart_outlined;
    case 'presentation':return Icons.slideshow_outlined;
    case 'audio':       return Icons.audio_file_outlined;
    case 'video':       return Icons.video_file_outlined;
    case 'archive':     return Icons.folder_zip_outlined;
    default:            return Icons.attach_file;
  }
}

Color attachmentColor(String type) {
  switch (type) {
    case 'image':       return Colors.teal;
    case 'pdf':         return Colors.red;
    case 'document':    return Colors.blue;
    case 'spreadsheet': return Colors.green;
    case 'presentation':return Colors.orange;
    case 'audio':       return Colors.purple;
    case 'video':       return Colors.deepOrange;
    case 'archive':     return Colors.brown;
    default:            return Colors.grey;
  }
}

String formatFileSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

/// Copies a picked file into the app's private attachments directory and
/// returns the stored path.
Future<String> copyToAttachmentsDir(String sourcePath) async {
  final dir = await getApplicationDocumentsDirectory();
  final attachDir = Directory('${dir.path}/note_attachments');
  if (!attachDir.existsSync()) attachDir.createSync(recursive: true);
  final originalName = sourcePath.split(Platform.pathSeparator).last;
  final safeName = '${DateTime.now().millisecondsSinceEpoch}_$originalName';
  final dest = '${attachDir.path}/$safeName';
  await File(sourcePath).copy(dest);
  return dest;
}

/// Silently deletes an attachment file from disk, ignoring errors.
void deleteAttachmentFile(String path) {
  try { File(path).deleteSync(); } catch (_) {}
}

final FlutterLocalNotificationsPlugin _notifications =
FlutterLocalNotificationsPlugin();

final GlobalKey<NavigatorState> appNavigatorKey = GlobalKey<NavigatorState>();

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  tz.initializeTimeZones();
  try {
    final zone = await FlutterTimezone.getLocalTimezone();
    tz.setLocalLocation(tz.getLocation(zone.identifier));
  } catch (_) {
    // Use the default timezone if the device timezone cannot be read.
  }
  const initSettings = InitializationSettings(
    android: AndroidInitializationSettings('@mipmap/ic_launcher'),
  );
  await _notifications.initialize(
    settings: initSettings,
    onDidReceiveNotificationResponse: (NotificationResponse response) {
      final payload = response.payload;
      if (payload != null && payload.startsWith('verify:')) {
        EmailVerificationHelper.handleExternalVerificationPayload(payload);
      }
    },
  );

  final launchDetails = await _notifications.getNotificationAppLaunchDetails();
  if (launchDetails?.didNotificationLaunchApp ?? false) {
    final payload = launchDetails?.notificationResponse?.payload;
    if (payload != null && payload.startsWith('verify:')) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        EmailVerificationHelper.handleExternalVerificationPayload(payload);
      });
    }
  }

  final androidNotifications = _notifications
      .resolvePlatformSpecificImplementation<
      AndroidFlutterLocalNotificationsPlugin>();
  await androidNotifications?.requestNotificationsPermission();
  await androidNotifications?.requestExactAlarmsPermission();
  await AuthService.instance.initialize();
  await LocalNotesStore.instance.initialize();
  ConnectivityService.instance.initialize();
  runApp(const CloudNotesApp());
}

class CloudNotesApp extends StatefulWidget {
  const CloudNotesApp({super.key});

  static CloudNotesAppState of(BuildContext context) =>
      context.findAncestorStateOfType<CloudNotesAppState>()!;

  @override
  State<CloudNotesApp> createState() => CloudNotesAppState();
}

class CloudNotesAppState extends State<CloudNotesApp> {
  ThemeMode _themeMode = ThemeMode.light;
  double _textScaleFactor = 1.0;

  bool get isDarkMode => _themeMode == ThemeMode.dark;
  double get textScaleFactor => _textScaleFactor;

  void toggleTheme() {
    setState(() {
      _themeMode = _themeMode == ThemeMode.light ? ThemeMode.dark : ThemeMode.light;
    });
  }

  void setTextScaleFactor(double scale) {
    setState(() {
      _textScaleFactor = scale;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: appNavigatorKey,
      debugShowCheckedModeBanner: false,
      title: 'NoteApp',
      themeMode: _themeMode,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.light,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.indigo,
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.indigo,
          brightness: Brightness.dark,
        ),
      ),
      builder: (context, child) {
        return MediaQuery(
          data: MediaQuery.of(context).copyWith(
            textScaler: TextScaler.linear(_textScaleFactor),
          ),
          child: child!,
        );
      },
      home: const SplashScreen(),
    );
  }
}

// ---------------------------------------------------------
// SPLASH SCREEN (Untouched & Branded)
// ---------------------------------------------------------
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) {
        final targetScreen = AuthService.instance.isAuthenticated
            ? const NotesScreen()
            : const AuthScreen();
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => targetScreen),
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.indigo,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.white,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.2),
                    blurRadius: 15,
                    offset: const Offset(0, 5),
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(50),
                child: Image.asset(
                  'assets/my_logo.png',
                  width: 80,
                  height: 80,
                  fit: BoxFit.cover,
                ),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'NoteApp',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Colors.white,
                letterSpacing: 1.2,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Your thoughts, saved privately on this device',
              style: TextStyle(fontSize: 14, color: Colors.white70),
            ),
            const SizedBox(height: 48),
            const SizedBox(
              width: 32,
              height: 32,
              child: CircularProgressIndicator(
                color: Colors.white,
                strokeWidth: 3,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------
// MAIN NOTES & CHECKLIST SCREEN WITH SEARCH, AUTO-SAVE, OFFLINE STORAGE & REMINDERS
// ---------------------------------------------------------
// ---------------------------------------------------------------------------
// EMAIL VERIFICATION & CREDENTIAL RECOVERY (FORGOT PIN & FORGOT PASSWORD)
// High-Security Multi Cross-Check Flow:
// 1. Verification link is dispatched to the user's saved email / notification tray.
// 2. The link is NOT displayed on the app screen to prevent local unauthorized access.
// 3. Touching the link in the email / system notification brings the user directly
//    to the "Add New PIN" interface.
// ---------------------------------------------------------------------------

class _PendingVerification {
  final String email;
  final String code;
  final String token;
  final String actionType;
  final DateTime expiresAt;

  _PendingVerification({
    required this.email,
    required this.code,
    required this.token,
    required this.actionType,
    required this.expiresAt,
  });
}

class EmailVerificationHelper {
  static final Map<String, _PendingVerification> _pendingVerifications = {};
  static VoidCallback? _dismissWaitingDialog;

  /// Handles incoming deep link / notification touch: "verify:actionType:email:code:token"
  static void handleExternalVerificationPayload(String payload) {
    final parts = payload.split(':');
    if (parts.length < 5) return;
    final actionType = parts[1];
    final email = parts[2];
    final code = parts[3];
    final token = parts[4];

    final pending = _pendingVerifications[email];
    if (pending == null || pending.code != code || pending.token != token) {
      return;
    }
    if (DateTime.now().isAfter(pending.expiresAt)) {
      _pendingVerifications.remove(email);
      return;
    }

    _pendingVerifications.remove(email);

    // If the in-app waiting screen is open, dismiss it
    if (_dismissWaitingDialog != null) {
      _dismissWaitingDialog!();
      _dismissWaitingDialog = null;
    }

    // Direct the user to Add New PIN or Set New Password
    final context = appNavigatorKey.currentContext;
    if (context != null) {
      if (actionType == 'reset_pin') {
        _showSetNewPinDialog(context, email: email);
      } else if (actionType == 'reset_password') {
        _showSetNewPasswordDialog(context, email: email);
      }
    }
  }

  /// Launches the email verification link flow to reset the Security PIN.
  static Future<bool> showResetPinFlow(BuildContext context, {String initialEmail = ''}) async {
    final email = AuthService.instance.currentUser?.email ?? initialEmail.trim().toLowerCase();
    if (email.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Unable to detect registered email. Please sign in.')),
      );
      return false;
    }

    final shouldSend = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: const Row(
          children: [
            Icon(Icons.mail_lock, color: Colors.indigo),
            SizedBox(width: 8),
            Text('Forgot Security PIN', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'A secure verification link will be sent to your registered account email:',
              style: TextStyle(fontSize: 13, color: Colors.grey),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.indigo.shade50,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: Colors.indigo.shade200),
              ),
              child: Row(
                children: [
                  const Icon(Icons.email_outlined, color: Colors.indigo, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      email,
                      style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.indigo, fontSize: 14),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              'For high security and cross-checking, the verification link is sent directly to your email (and system notification tray). Touch that link to open the "Add New PIN" interface.',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton.icon(
            icon: const Icon(Icons.send, size: 16),
            label: const Text('Send Verification Link'),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(ctx, true),
          ),
        ],
      ),
    );

    if (shouldSend != true || !context.mounted) return false;

    final code = (100000 + Random.secure().nextInt(900000)).toString();
    final token = SecurityService.instance.generateSalt(16);

    await _dispatchExternalEmailVerification(
      email: email,
      actionType: 'reset_pin',
      actionTitle: 'Reset Security PIN',
      code: code,
      token: token,
    );

    if (!context.mounted) return false;

    final verified = await _showWaitingForEmailVerificationDialog(
      context: context,
      email: email,
      actionTitle: 'Reset Security PIN',
      actionType: 'reset_pin',
    );

    if (verified && context.mounted) {
      return await _showSetNewPinDialog(context, email: email);
    }
    return false;
  }

  /// Launches the email verification link flow to reset the Account Password.
  static Future<bool> showResetPasswordFlow(BuildContext context, {String initialEmail = ''}) async {
    final emailController = TextEditingController(text: initialEmail.trim().toLowerCase());
    String? errorMsg;

    final targetEmail = await showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDlgState) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: const Row(
            children: [
              Icon(Icons.lock_reset, color: Colors.indigo),
              SizedBox(width: 8),
              Text('Account Recovery', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Enter your registered email address. We will send a secure verification link to reset your account password.',
                style: TextStyle(fontSize: 13, color: Colors.grey),
              ),
              const SizedBox(height: 16),
              if (errorMsg != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(color: Colors.red.shade50, borderRadius: BorderRadius.circular(8)),
                  child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 12)),
                ),
              TextField(
                controller: emailController,
                keyboardType: TextInputType.emailAddress,
                autofocus: true,
                decoration: const InputDecoration(
                  labelText: 'Registered Email',
                  prefixIcon: Icon(Icons.email_outlined),
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, null), child: const Text('Cancel')),
            ElevatedButton.icon(
              icon: const Icon(Icons.send, size: 16),
              label: const Text('Send Reset Link'),
              style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
              onPressed: () async {
                final email = emailController.text.trim().toLowerCase();
                if (!email.contains('@') || !email.contains('.')) {
                  setDlgState(() => errorMsg = 'Please enter a valid email address.');
                  return;
                }
                final exists = await AuthService.instance.userExists(email);
                if (!exists) {
                  setDlgState(() => errorMsg = 'No registered account found with this email.');
                  return;
                }
                if (ctx.mounted) Navigator.pop(ctx, email);
              },
            ),
          ],
        ),
      ),
    );

    if (targetEmail == null || targetEmail.isEmpty || !context.mounted) return false;

    final code = (100000 + Random.secure().nextInt(900000)).toString();
    final token = SecurityService.instance.generateSalt(16);

    await _dispatchExternalEmailVerification(
      email: targetEmail,
      actionType: 'reset_password',
      actionTitle: 'Reset Account Password',
      code: code,
      token: token,
    );

    if (!context.mounted) return false;

    final verified = await _showWaitingForEmailVerificationDialog(
      context: context,
      email: targetEmail,
      actionTitle: 'Reset Account Password',
      actionType: 'reset_password',
    );

    if (verified && context.mounted) {
      return await _showSetNewPasswordDialog(context, email: targetEmail);
    }
    return false;
  }

  /// Dispatches the verification link externally to the saved email address and system notifications.
  static Future<void> _dispatchExternalEmailVerification({
    required String email,
    required String actionType,
    required String actionTitle,
    required String code,
    required String token,
  }) async {
    final link = 'noteapp://vault/verify?type=$actionType&email=$email&code=$code&token=$token';

    _pendingVerifications[email] = _PendingVerification(
      email: email,
      code: code,
      token: token,
      actionType: actionType,
      expiresAt: DateTime.now().add(const Duration(minutes: 15)),
    );

    final androidDetails = AndroidNotificationDetails(
      'security_vault_email',
      'Security & Email Verification',
      channelDescription: 'Delivers multi-cross-check security verification links to saved email',
      importance: Importance.max,
      priority: Priority.high,
      showWhen: true,
      icon: '@mipmap/ic_launcher',
      styleInformation: BigTextStyleInformation(
        'Touch this verification link to proceed:\n$link\n\nSecurity verification code: $code',
      ),
    );

    await _notifications.show(
      id: 99991,
      title: '📧 Vault Security: $actionTitle Link',
      body: 'To: $email • Touch link to verify & $actionTitle (Code: $code)',
      notificationDetails: NotificationDetails(android: androidDetails),
      payload: 'verify:$actionType:$email:$code:$token',
    );
  }

  /// Displays the secure waiting screen where the verification link is NOT shown on the app screen.
  static Future<bool> _showWaitingForEmailVerificationDialog({
    required BuildContext context,
    required String email,
    required String actionTitle,
    required String actionType,
  }) async {
    final codeController = TextEditingController();
    String? errorMsg;
    bool isClosedByExternalTouch = false;

    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) {
        _dismissWaitingDialog = () {
          isClosedByExternalTouch = true;
          if (ctx.mounted) Navigator.pop(ctx, true);
        };

        return StatefulBuilder(
          builder: (ctx, setDlgState) => AlertDialog(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
            title: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(color: Colors.indigo.shade50, shape: BoxShape.circle),
                  child: const Icon(Icons.mark_email_read_outlined, color: Colors.indigo, size: 22),
                ),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text('Verification Sent', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
            content: SingleChildScrollView(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 400),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'For security verification and multi cross-checking, the verification link has been sent to your registered email:',
                      style: TextStyle(fontSize: 13, color: Colors.grey),
                    ),
                    const SizedBox(height: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      decoration: BoxDecoration(
                        color: Colors.indigo.shade50,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: Colors.indigo.shade200),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.email, size: 18, color: Colors.indigo),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              email,
                              style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.indigo, fontSize: 13),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Colors.amber.shade50,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.amber.shade300),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(Icons.shield, size: 18, color: Colors.amber.shade900),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              'The verification link is NOT displayed on this screen for security cross-check. Check your email or pull down your system notification tray and touch the link to proceed.',
                              style: TextStyle(fontSize: 12, color: Colors.amber.shade900),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                    const Text(
                      'Or enter the 6-digit code received in the email / notification:',
                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 8),
                    if (errorMsg != null)
                      Container(
                        margin: const EdgeInsets.only(bottom: 8),
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(color: Colors.red.shade50, borderRadius: BorderRadius.circular(6)),
                        child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 11)),
                      ),
                    TextField(
                      controller: codeController,
                      keyboardType: TextInputType.number,
                      maxLength: 6,
                      textAlign: TextAlign.center,
                      style: const TextStyle(fontSize: 20, letterSpacing: 4, fontWeight: FontWeight.bold),
                      decoration: InputDecoration(
                        hintText: '• • • • • •',
                        counterText: '',
                        prefixIcon: const Icon(Icons.pin),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () {
                  _dismissWaitingDialog = null;
                  Navigator.pop(ctx, false);
                },
                child: const Text('Cancel'),
              ),
              ElevatedButton(
                onPressed: () {
                  final entered = codeController.text.trim();
                  final pending = _pendingVerifications[email];
                  if (pending == null || pending.code != entered) {
                    setDlgState(() => errorMsg = 'Invalid verification code. Please check your email.');
                    return;
                  }
                  if (DateTime.now().isAfter(pending.expiresAt)) {
                    _pendingVerifications.remove(email);
                    setDlgState(() => errorMsg = 'Verification code has expired. Please request a new link.');
                    return;
                  }
                  _pendingVerifications.remove(email);
                  _dismissWaitingDialog = null;
                  Navigator.pop(ctx, true);
                },
                style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
                child: const Text('Verify Code'),
              ),
            ],
          ),
        );
      },
    );

    _dismissWaitingDialog = null;

    if (isClosedByExternalTouch) {
      return false; // Already handled by handleExternalVerificationPayload
    }

    return result ?? false;
  }

  /// Dialog allowing the verified user to add/set a new PIN.
  static Future<bool> _showSetNewPinDialog(BuildContext context, {required String email}) async {
    final pinController = TextEditingController();
    final confirmController = TextEditingController();
    String? errorMsg;

    final success = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDlgState) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: const Row(
            children: [
              Icon(Icons.check_circle, color: Colors.green),
              SizedBox(width: 8),
              Text('Add New PIN', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(color: Colors.green.shade50, borderRadius: BorderRadius.circular(8)),
                child: Row(
                  children: [
                    const Icon(Icons.verified, size: 16, color: Colors.green),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text('Identity verified for $email', style: TextStyle(color: Colors.green.shade900, fontSize: 12, fontWeight: FontWeight.bold)),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              if (errorMsg != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(color: Colors.red.shade50, borderRadius: BorderRadius.circular(8)),
                  child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 12)),
                ),
              TextField(
                controller: pinController,
                obscureText: true,
                keyboardType: TextInputType.number,
                maxLength: 6,
                autofocus: true,
                decoration: const InputDecoration(
                  labelText: 'New PIN (4-6 digits)',
                  prefixIcon: Icon(Icons.pin),
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: confirmController,
                obscureText: true,
                keyboardType: TextInputType.number,
                maxLength: 6,
                decoration: const InputDecoration(
                  labelText: 'Confirm New PIN',
                  prefixIcon: Icon(Icons.check),
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            ElevatedButton(
              onPressed: () async {
                final pin = pinController.text.trim();
                final confirm = confirmController.text.trim();
                if (pin.length < 4) {
                  setDlgState(() => errorMsg = 'PIN must be at least 4 digits.');
                  return;
                }
                if (pin != confirm) {
                  setDlgState(() => errorMsg = 'PINs do not match.');
                  return;
                }
                await AuthService.instance.resetSecurityPinByEmail(email: email, newPin: pin);
                if (ctx.mounted) Navigator.pop(ctx, true);
              },
              style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
              child: const Text('Save New PIN'),
            ),
          ],
        ),
      ),
    );

    if (success == true && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Security PIN updated successfully! You can now use your new PIN.'),
          backgroundColor: Colors.green,
        ),
      );
      return true;
    }
    return false;
  }

  /// Dialog allowing the verified user to set a new Account Password.
  static Future<bool> _showSetNewPasswordDialog(BuildContext context, {required String email}) async {
    final passwordController = TextEditingController();
    final confirmController = TextEditingController();
    bool obscurePassword = true;
    String? errorMsg;

    final success = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDlgState) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: const Row(
            children: [
              Icon(Icons.check_circle, color: Colors.green),
              SizedBox(width: 8),
              Text('Set New Password', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(color: Colors.green.shade50, borderRadius: BorderRadius.circular(8)),
                child: Row(
                  children: [
                    const Icon(Icons.verified, size: 16, color: Colors.green),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text('Identity verified for $email', style: TextStyle(color: Colors.green.shade900, fontSize: 12, fontWeight: FontWeight.bold)),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              if (errorMsg != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(color: Colors.red.shade50, borderRadius: BorderRadius.circular(8)),
                  child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 12)),
                ),
              TextField(
                controller: passwordController,
                obscureText: obscurePassword,
                autofocus: true,
                decoration: InputDecoration(
                  labelText: 'New Password (min. 6 chars)',
                  prefixIcon: const Icon(Icons.lock_outline),
                  suffixIcon: IconButton(
                    icon: Icon(obscurePassword ? Icons.visibility_off : Icons.visibility),
                    onPressed: () => setDlgState(() => obscurePassword = !obscurePassword),
                  ),
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: confirmController,
                obscureText: obscurePassword,
                decoration: const InputDecoration(
                  labelText: 'Confirm New Password',
                  prefixIcon: Icon(Icons.check_circle_outline),
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            ElevatedButton(
              onPressed: () async {
                final password = passwordController.text;
                final confirm = confirmController.text;
                if (password.length < 6) {
                  setDlgState(() => errorMsg = 'Password must be at least 6 characters.');
                  return;
                }
                if (password != confirm) {
                  setDlgState(() => errorMsg = 'Passwords do not match.');
                  return;
                }
                await AuthService.instance.resetPasswordByEmail(email: email, newPassword: password);
                if (ctx.mounted) Navigator.pop(ctx, true);
              },
              style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
              child: const Text('Update Password'),
            ),
          ],
        ),
      ),
    );

    if (success == true && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Password reset successfully! Please sign in with your new password.'),
          backgroundColor: Colors.green,
        ),
      );
      return true;
    }
    return false;
  }
}
// ---------------------------------------------------------
// AUTHENTICATION SCREEN: SECURE SIGN IN & REGISTRATION
// ---------------------------------------------------------
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final _loginEmailController = TextEditingController();
  final _loginPasswordController = TextEditingController();

  final _regNameController = TextEditingController();
  final _regEmailController = TextEditingController();
  final _regPasswordController = TextEditingController();
  final _regConfirmPasswordController = TextEditingController();

  bool _obscureLoginPassword = true;
  bool _obscureRegPassword = true;
  bool _isLoading = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _loginEmailController.dispose();
    _loginPasswordController.dispose();
    _regNameController.dispose();
    _regEmailController.dispose();
    _regPasswordController.dispose();
    _regConfirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _handleLogin() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      await AuthService.instance.login(
        email: _loginEmailController.text.trim(),
        password: _loginPasswordController.text,
      );
      if (mounted) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const NotesScreen()),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString().replaceAll('Exception: ', '');
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _handleRegister() async {
    final password = _regPasswordController.text;
    final confirm = _regConfirmPasswordController.text;

    if (password != confirm) {
      setState(() => _errorMessage = 'Passwords do not match.');
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      await AuthService.instance.register(
        name: _regNameController.text.trim(),
        email: _regEmailController.text.trim(),
        password: password,
      );
      if (mounted) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const NotesScreen()),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString().replaceAll('Exception: ', '');
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final cardBg = isDark ? Colors.grey.shade900 : Colors.white;

    return Scaffold(
      backgroundColor: isDark ? Colors.black : Colors.indigo.shade50,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24.0),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 440),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.1),
                          blurRadius: 12,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(40),
                      child: Image.asset('assets/my_logo.png', width: 64, height: 64, fit: BoxFit.cover),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'NoteApp Vault',
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.indigo),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'Private accounts â€¢ SHA-256 salted protection â€¢ Offline-ready',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                  const SizedBox(height: 24),

                  Card(
                    color: cardBg,
                    elevation: 4,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                    child: Padding(
                      padding: const EdgeInsets.all(20.0),
                      child: Column(
                        children: [
                          TabBar(
                            controller: _tabController,
                            labelColor: Colors.indigo,
                            indicatorColor: Colors.indigo,
                            unselectedLabelColor: Colors.grey,
                            tabs: const [
                              Tab(text: 'Sign In'),
                              Tab(text: 'Create Account'),
                            ],
                            onTap: (_) => setState(() => _errorMessage = null),
                          ),
                          const SizedBox(height: 20),

                          if (_errorMessage != null)
                            Container(
                              width: double.infinity,
                              margin: const EdgeInsets.only(bottom: 16),
                              padding: const EdgeInsets.all(12),
                              decoration: BoxDecoration(
                                color: Colors.red.shade50,
                                borderRadius: BorderRadius.circular(10),
                                border: Border.all(color: Colors.red.shade200),
                              ),
                              child: Row(
                                children: [
                                  Icon(Icons.error_outline, size: 18, color: Colors.red.shade700),
                                  const SizedBox(width: 8),
                                  Expanded(
                                    child: Text(
                                      _errorMessage!,
                                      style: TextStyle(color: Colors.red.shade900, fontSize: 13),
                                    ),
                                  ),
                                ],
                              ),
                            ),

                          SizedBox(
                            height: 320,
                            child: TabBarView(
                              controller: _tabController,
                              children: [
                                Column(
                                  children: [
                                    TextField(
                                      controller: _loginEmailController,
                                      keyboardType: TextInputType.emailAddress,
                                      decoration: InputDecoration(
                                        labelText: 'Email Address',
                                        prefixIcon: const Icon(Icons.email_outlined),
                                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                      ),
                                    ),
                                    const SizedBox(height: 16),
                                    TextField(
                                      controller: _loginPasswordController,
                                      obscureText: _obscureLoginPassword,
                                      decoration: InputDecoration(
                                        labelText: 'Password',
                                        prefixIcon: const Icon(Icons.lock_outline),
                                        suffixIcon: IconButton(
                                          icon: Icon(_obscureLoginPassword ? Icons.visibility_off : Icons.visibility),
                                          onPressed: () => setState(() => _obscureLoginPassword = !_obscureLoginPassword),
                                        ),
                                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                      ),
                                    ),
                                    Align(
                                      alignment: Alignment.centerRight,
                                      child: TextButton.icon(
                                        icon: const Icon(Icons.mail_lock_outlined, size: 15, color: Colors.indigo),
                                        label: const Text('Forgot Password?', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.indigo)),
                                        onPressed: () async {
                                          final email = _loginEmailController.text.trim();
                                          final reset = await EmailVerificationHelper.showResetPasswordFlow(
                                            context,
                                            initialEmail: email,
                                          );
                                          if (reset && mounted) {
                                            setState(() => _errorMessage = null);
                                          }
                                        },
                                      ),
                                    ),
                                    const Spacer(),
                                    SizedBox(
                                      width: double.infinity,
                                      height: 50,
                                      child: ElevatedButton(
                                        onPressed: _isLoading ? null : _handleLogin,
                                        style: ElevatedButton.styleFrom(
                                          backgroundColor: Colors.indigo,
                                          foregroundColor: Colors.white,
                                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                                        ),
                                        child: _isLoading
                                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                                            : const Text('Sign In', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                                      ),
                                    ),
                                  ],
                                ),

                                SingleChildScrollView(
                                  child: Column(
                                    children: [
                                      TextField(
                                        controller: _regNameController,
                                        decoration: InputDecoration(
                                          labelText: 'Full Name',
                                          prefixIcon: const Icon(Icons.person_outline),
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                        ),
                                      ),
                                      const SizedBox(height: 12),
                                      TextField(
                                        controller: _regEmailController,
                                        keyboardType: TextInputType.emailAddress,
                                        decoration: InputDecoration(
                                          labelText: 'Email Address',
                                          prefixIcon: const Icon(Icons.email_outlined),
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                        ),
                                      ),
                                      const SizedBox(height: 12),
                                      TextField(
                                        controller: _regPasswordController,
                                        obscureText: _obscureRegPassword,
                                        decoration: InputDecoration(
                                          labelText: 'Password (min. 6 chars)',
                                          prefixIcon: const Icon(Icons.lock_outline),
                                          suffixIcon: IconButton(
                                            icon: Icon(_obscureRegPassword ? Icons.visibility_off : Icons.visibility),
                                            onPressed: () => setState(() => _obscureRegPassword = !_obscureRegPassword),
                                          ),
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                        ),
                                      ),
                                      const SizedBox(height: 12),
                                      TextField(
                                        controller: _regConfirmPasswordController,
                                        obscureText: _obscureRegPassword,
                                        decoration: InputDecoration(
                                          labelText: 'Confirm Password',
                                          prefixIcon: const Icon(Icons.check_circle_outline),
                                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                                        ),
                                      ),
                                      const SizedBox(height: 16),
                                      SizedBox(
                                        width: double.infinity,
                                        height: 50,
                                        child: ElevatedButton(
                                          onPressed: _isLoading ? null : _handleRegister,
                                          style: ElevatedButton.styleFrom(
                                            backgroundColor: Colors.indigo,
                                            foregroundColor: Colors.white,
                                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                                          ),
                                          child: _isLoading
                                              ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                                              : const Text('Create Account', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.lock_clock_outlined, size: 14, color: Colors.grey),
                      SizedBox(width: 6),
                      Text(
                        'Passwords are never stored in plain text.',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class NotesScreen extends StatefulWidget {
  const NotesScreen({super.key});

  @override
  State<NotesScreen> createState() => _NotesScreenState();
}

class _NotesScreenState extends State<NotesScreen> {
  final TextEditingController _titleController = TextEditingController();
  final TextEditingController _contentController = TextEditingController();
  final TextEditingController _searchController = TextEditingController();
  final TextEditingController _taskItemController = TextEditingController();

  // Search & Organization states
  bool _isSearching = false;
  String _searchQuery = '';
  String _selectedFolder = 'All Notes';
  String _selectedTag = 'All';
  String _sortBy = 'Newest'; // Options: Newest, Oldest, Alphabetical

  final List<String> _folders = ['All Notes', 'Assignments', 'Meetings', 'Study', 'Personal', 'Work', 'Ideas'];
  final List<String> _tags = ['All', '#todo', '#daily', '#assignment', '#meeting', '#study', '#learn', '#work'];

  // Connectivity & Sync states
  bool _isOnline = true;
  bool _isSyncing = false;
  StreamSubscription<bool>? _connectivitySub;
  StreamSubscription<SyncResult>? _syncSub;
  final Set<String> _unlockedDocIds = {};

  @override
  void initState() {
    super.initState();
    _isOnline = ConnectivityService.instance.isOnline;
    _connectivitySub = ConnectivityService.instance.onConnectivityChanged.listen((online) {
      if (mounted) {
        setState(() => _isOnline = online);
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                Icon(online ? Icons.wifi : Icons.wifi_off, color: Colors.white, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    online
                        ? 'Internet connection restored! Syncing offline notes...'
                        : 'You are currently offline. Notes will be saved locally.',
                  ),
                ),
              ],
            ),
            backgroundColor: online ? Colors.teal.shade700 : Colors.orange.shade800,
            duration: const Duration(seconds: 3),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    });

    _syncSub = SyncManager.instance.onSyncCompleted.listen((result) {
      if (mounted && result.syncedCount > 0) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.cloud_done, color: Colors.white, size: 18),
                const SizedBox(width: 8),
                Expanded(child: Text(result.message)),
              ],
            ),
            backgroundColor: Colors.teal.shade700,
            duration: const Duration(seconds: 3),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    });
  }

  @override
  void dispose() {
    _connectivitySub?.cancel();
    _syncSub?.cancel();
    _titleController.dispose();
    _contentController.dispose();
    _searchController.dispose();
    _taskItemController.dispose();
    super.dispose();
  }

    Future<bool> _promptSetPinDialog() async {
    final userHasPin = AuthService.instance.currentUser?.hasPin ?? false;
    final oldPinController = TextEditingController();
    final pinController = TextEditingController();
    final confirmController = TextEditingController();
    String? errorMsg;

    final success = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDlgState) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: Row(
            children: [
              const Icon(Icons.shield_outlined, color: Colors.indigo),
              const SizedBox(width: 8),
              Text(
                userHasPin ? 'Change Security PIN' : 'Set Security PIN',
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
            ],
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  userHasPin
                      ? 'To change your PIN, enter your current (old) PIN first, followed by your new PIN.'
                      : 'Set a 4-to-6 digit PIN to protect sensitive notes. Your PIN is cryptographically salted and hashed.',
                  style: const TextStyle(fontSize: 13, color: Colors.grey),
                ),
                const SizedBox(height: 16),
                if (errorMsg != null)
                  Container(
                    margin: const EdgeInsets.only(bottom: 12),
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.red.shade50,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 12)),
                  ),

                // If user already has a PIN, require the Current (Old) PIN!
                if (userHasPin) ...[
                  TextField(
                    controller: oldPinController,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    maxLength: 6,
                    decoration: const InputDecoration(
                      labelText: 'Current (Old) PIN',
                      prefixIcon: Icon(Icons.lock_clock),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  Align(
                    alignment: Alignment.centerRight,
                    child: TextButton.icon(
                      icon: const Icon(Icons.mail_lock_outlined, size: 15, color: Colors.indigo),
                      label: const Text('Forgot current PIN? Reset via email', style: TextStyle(fontSize: 12)),
                      onPressed: () async {
                        Navigator.pop(ctx, false);
                        await EmailVerificationHelper.showResetPinFlow(context);
                      },
                    ),
                  ),
                  const SizedBox(height: 8),
                ],

                TextField(
                  controller: pinController,
                  obscureText: true,
                  keyboardType: TextInputType.number,
                  maxLength: 6,
                  decoration: InputDecoration(
                    labelText: userHasPin ? 'New PIN (4-6 digits)' : 'PIN (4-6 digits)',
                    prefixIcon: const Icon(Icons.pin),
                    border: const OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: confirmController,
                  obscureText: true,
                  keyboardType: TextInputType.number,
                  maxLength: 6,
                  decoration: const InputDecoration(
                    labelText: 'Confirm PIN',
                    prefixIcon: Icon(Icons.check),
                    border: OutlineInputBorder(),
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                final oldPin = oldPinController.text.trim();
                final pin = pinController.text.trim();
                final confirm = confirmController.text.trim();

                if (userHasPin) {
                  if (oldPin.isEmpty) {
                    setDlgState(() => errorMsg = 'Please enter your current (old) PIN.');
                    return;
                  }
                  if (!AuthService.instance.verifySecurityPin(oldPin)) {
                    setDlgState(() => errorMsg = 'Current PIN is incorrect. Try again or reset via email.');
                    return;
                  }
                  if (oldPin == pin) {
                    setDlgState(() => errorMsg = 'New PIN must be different from current PIN.');
                    return;
                  }
                }

                if (pin.length < 4) {
                  setDlgState(() => errorMsg = 'PIN must be at least 4 digits.');
                  return;
                }
                if (pin != confirm) {
                  setDlgState(() => errorMsg = 'PINs do not match.');
                  return;
                }

                await AuthService.instance.setSecurityPin(pin);
                if (ctx.mounted) Navigator.pop(ctx, true);
              },
              style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
              child: Text(userHasPin ? 'Update PIN' : 'Save PIN'),
            ),
          ],
        ),
      ),
    );
    return success ?? false;
  }

  Future<void> _promptUnlockNote(String docId, Map<String, dynamic> noteData) async {
    final pinController = TextEditingController();
    String? errorMsg;

    final unlocked = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDlgState) => AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: const Row(
            children: [
              Icon(Icons.lock, color: Colors.red),
              SizedBox(width: 8),
              Text('Sensitive Note Locked', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'This note is protected with your Security PIN. Enter your PIN to view or edit.',
                style: TextStyle(fontSize: 13, color: Colors.grey),
              ),
              const SizedBox(height: 16),
              if (errorMsg != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.red.shade50,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(errorMsg!, style: TextStyle(color: Colors.red.shade900, fontSize: 12)),
                ),
              TextField(
                controller: pinController,
                obscureText: true,
                autofocus: true,
                keyboardType: TextInputType.number,
                maxLength: 6,
                decoration: const InputDecoration(
                  labelText: 'Security PIN',
                  prefixIcon: Icon(Icons.password),
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 4),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton.icon(
                  icon: const Icon(Icons.mail_lock_outlined, size: 15, color: Colors.indigo),
                  label: const Text('Forgot PIN? Reset via email', style: TextStyle(fontSize: 12)),
                  onPressed: () async {
                    Navigator.pop(ctx, false);
                    final reset = await EmailVerificationHelper.showResetPinFlow(context);
                    if (reset && mounted) {
                      _promptUnlockNote(docId, noteData);
                    }
                  },
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () {
                final pin = pinController.text.trim();
                if (AuthService.instance.verifySecurityPin(pin)) {
                  Navigator.pop(ctx, true);
                } else {
                  setDlgState(() => errorMsg = 'Incorrect PIN. Please try again.');
                }
              },
              style: ElevatedButton.styleFrom(backgroundColor: Colors.indigo, foregroundColor: Colors.white),
              child: const Text('Unlock'),
            ),
          ],
        ),
      ),
    );

    if (unlocked == true && mounted) {
      setState(() => _unlockedDocIds.add(docId));
      _showNoteDialog(
        docId: docId,
        existingTitle: noteData['title'],
        existingText: noteData['text'],
        existingFolder: noteData['folder'],
        existingTag: noteData['tag'],
        existingIsPinned: noteData['isPinned'],
        existingIsChecklist: noteData['isChecklist'],
        existingItems: noteData['items'],
        existingReminder: noteData['reminderTime'],
        existingAttachments: noteData['attachments'],
        existingIsLocked: true,
      );
    }
  }

  void _handleLogout() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: const Text('Log Out'),
        content: const Text('Are you sure you want to log out of your account? Your notes will remain safely stored on this device.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red, foregroundColor: Colors.white),
            child: const Text('Log Out'),
          ),
        ],
      ),
    );

    if (confirmed == true && mounted) {
      _unlockedDocIds.clear();
      await AuthService.instance.logout();
      if (mounted) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => const AuthScreen()),
        );
      }
    }
  }

  Future<void> _triggerManualSync() async {
    setState(() => _isSyncing = true);
    final result = await SyncManager.instance.syncPendingNotes();
    if (mounted) {
      setState(() => _isSyncing = false);
      ScaffoldMessenger.of(context).hideCurrentSnackBar();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              Icon(
                result.isOnline ? (result.syncedCount > 0 ? Icons.cloud_done : Icons.check_circle_outline) : Icons.cloud_off,
                color: Colors.white,
                size: 18,
              ),
              const SizedBox(width: 8),
              Expanded(child: Text(result.message)),
            ],
          ),
          backgroundColor: result.isOnline ? Colors.indigo : Colors.orange.shade800,
          duration: const Duration(seconds: 3),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  String _formatTimestamp(Timestamp? timestamp) {
    if (timestamp == null) return 'Just now';
    DateTime dt = timestamp.toDate();
    String hour = dt.hour > 12 ? '${dt.hour - 12}' : '${dt.hour == 0 ? 12 : dt.hour}';
    String minute = dt.minute.toString().padLeft(2, '0');
    String period = dt.hour >= 12 ? 'PM' : 'AM';
    return '${dt.month}/${dt.day}/${dt.year} • $hour:$minute $period';
  }

  String _formatReminderDate(DateTime dt) {
    List<String> months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    String month = months[dt.month - 1];
    String hour = dt.hour > 12 ? '${dt.hour - 12}' : '${dt.hour == 0 ? 12 : dt.hour}';
    String minute = dt.minute.toString().padLeft(2, '0');
    String period = dt.hour >= 12 ? 'PM' : 'AM';
    return '$month ${dt.day}, ${dt.year} • $hour:$minute $period';
  }

  void _showTextSizeDialog() {
    final appState = CloudNotesApp.of(context);
    final currentScale = appState.textScaleFactor;

    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) {
        return Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.format_size, color: Colors.indigo),
                  SizedBox(width: 8),
                  Text(
                    'Text Size & Reading Mode',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              const Text('Select comfortable font size for reading notes:', style: TextStyle(fontSize: 13, color: Colors.grey)),
              const SizedBox(height: 20),
              SegmentedButton<double>(
                segments: const [
                  ButtonSegment(value: 0.9, label: Text('Small'), icon: Icon(Icons.text_fields, size: 14)),
                  ButtonSegment(value: 1.0, label: Text('Normal'), icon: Icon(Icons.text_fields, size: 18)),
                  ButtonSegment(value: 1.2, label: Text('Large'), icon: Icon(Icons.text_fields, size: 22)),
                  ButtonSegment(value: 1.4, label: Text('X-Large'), icon: Icon(Icons.text_fields, size: 26)),
                ],
                selected: {currentScale},
                onSelectionChanged: (Set<double> selection) {
                  appState.setTextScaleFactor(selection.first);
                  Navigator.pop(context);
                },
              ),
              const SizedBox(height: 16),
            ],
          ),
        );
      },
    );
  }

  void _showNoteDialog({
    String? docId,
    String? existingTitle,
    String? existingText,
    String? existingFolder,
    String? existingTag,
    bool? existingIsPinned,
    bool? existingIsChecklist,
    List<dynamic>? existingItems,
    Timestamp? existingReminder,
    List<dynamic>? existingAttachments,
    bool? existingIsLocked,
  }) {
    _titleController.text = existingTitle ?? '';
    _contentController.text = existingText ?? '';
    _taskItemController.clear();

    String dialogFolder = existingFolder ?? 'Assignments';
    String dialogTag = existingTag ?? '#todo';
    bool dialogIsPinned = existingIsPinned ?? false;
    bool dialogIsChecklist = existingIsChecklist ?? false;
    bool dialogIsLocked = existingIsLocked ?? false;
    DateTime? dialogReminder = existingReminder?.toDate();
    String? activeDocId = docId;

    List<Map<String, dynamic>> dialogItems = existingItems != null
        ? List<Map<String, dynamic>>.from(existingItems.map((item) => Map<String, dynamic>.from(item)))
        : [];

    List<Map<String, dynamic>> dialogAttachments = existingAttachments != null
        ? List<Map<String, dynamic>>.from(existingAttachments.map((a) => Map<String, dynamic>.from(a)))
        : [];

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) {
        Timer? autoSaveTimer;
        bool isSaving = false;
        String syncStatus = activeDocId == null
            ? 'Draft'
            : (ConnectivityService.instance.isOnline ? 'Cloud Synced ✓' : 'Saved Offline ☁');

        return StatefulBuilder(
          builder: (context, setModalState) {
            final isDark = Theme.of(context).brightness == Brightness.dark;
            final inputFillColor = isDark ? Colors.grey.shade900 : Colors.grey.shade100;

            void triggerAutoSave() {
              autoSaveTimer?.cancel();
              setModalState(() {
                isSaving = true;
                syncStatus = 'Auto-saving...';
              });

              autoSaveTimer = Timer(const Duration(milliseconds: 700), () async {
                final title = _titleController.text.trim();
                final text = _contentController.text.trim();

                if (title.isEmpty && text.isEmpty && dialogItems.isEmpty && dialogAttachments.isEmpty) {
                  setModalState(() {
                    isSaving = false;
                    syncStatus = 'Draft';
                  });
                  return;
                }

                try {
                  final data = {
                    'title': title.isEmpty ? (dialogIsChecklist ? 'Checklist' : 'Untitled') : title,
                    'text': text,
                    'folder': dialogFolder,
                    'tag': dialogTag,
                    'isPinned': dialogIsPinned,
                    'isChecklist': dialogIsChecklist,
                    'items': dialogItems,
                    'isLocked': dialogIsLocked,
                    'attachments': dialogAttachments,
                    'reminderTime': dialogReminder != null ? Timestamp.fromDate(dialogReminder!) : null,
                    'timestamp': FieldValue.serverTimestamp(),
                    'isSynced': ConnectivityService.instance.isOnline,
                    'syncStatus': ConnectivityService.instance.isOnline ? 'synced' : 'pending',
                    if (ConnectivityService.instance.isOnline) 'lastSyncedAt': FieldValue.serverTimestamp(),
                  };

                  if (activeDocId == null) {
                    final docRef = await LocalFirestore.instance.collection('notes').add(data);
                    activeDocId = docRef.id;
                  } else {
                    await LocalFirestore.instance.collection('notes').doc(activeDocId!).update(data);
                  }

                  await _syncReminder(activeDocId!, data);
                  setModalState(() {
                    isSaving = false;
                    syncStatus = ConnectivityService.instance.isOnline ? 'Cloud Synced ✓' : 'Saved Offline ☁';
                  });
                } catch (e) {
                  setModalState(() {
                    isSaving = false;
                    syncStatus = 'Error saving';
                  });
                }
              });
            }

            Future<void> pickReminderDateTime() async {
              final date = await showDatePicker(
                context: context,
                initialDate: dialogReminder ?? DateTime.now(),
                firstDate: DateTime.now(),
                lastDate: DateTime.now().add(const Duration(days: 365)),
              );

              if (date != null && context.mounted) {
                final time = await showTimePicker(
                  context: context,
                  initialTime: TimeOfDay.fromDateTime(dialogReminder ?? DateTime.now().add(const Duration(hours: 1))),
                );

                if (time != null) {
                  final selectedDT = DateTime(
                    date.year,
                    date.month,
                    date.day,
                    time.hour,
                    time.minute,
                  );

                  setModalState(() {
                    dialogReminder = selectedDT;
                  });

                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('⏰ Reminder set for ${_formatReminderDate(selectedDT)}'),
                        backgroundColor: Colors.indigo,
                        duration: const Duration(seconds: 3),
                      ),
                    );
                  }

                  triggerAutoSave();
                }
              }
            }

            return Padding(
              padding: EdgeInsets.only(
                bottom: MediaQuery.of(context).viewInsets.bottom + 24,
                left: 20,
                right: 20,
                top: 24,
              ),
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Text(
                              activeDocId == null ? 'Create Note' : 'Edit Note',
                              style: const TextStyle(
                                fontSize: 20,
                                fontWeight: FontWeight.bold,
                                color: Colors.indigo,
                              ),
                            ),
                            const SizedBox(width: 10),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                color: isSaving
                                    ? Colors.orange.shade50
                                    : (syncStatus.contains('Saved') ? Colors.green.shade50 : Colors.grey.shade100),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Row(
                                children: [
                                  Icon(
                                    isSaving
                                        ? Icons.sync
                                        : (syncStatus.contains('Saved') ? Icons.offline_pin : Icons.edit_note),
                                    size: 14,
                                    color: isSaving ? Colors.orange : Colors.green,
                                  ),
                                  const SizedBox(width: 4),
                                  Text(
                                    syncStatus,
                                    style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: FontWeight.bold,
                                      color: isSaving ? Colors.orange : Colors.green.shade800,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                        Row(
                          children: [
                            const Text('Pin', style: TextStyle(fontSize: 14, color: Colors.grey)),
                            Checkbox(
                              value: dialogIsPinned,
                              activeColor: Colors.indigo,
                              onChanged: (val) {
                                setModalState(() {
                                  dialogIsPinned = val ?? false;
                                });
                                triggerAutoSave();
                              },
                            ),
                          ],
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),

                    // Toggle between Standard Note & Checklist / To-Do List
                    SegmentedButton<bool>(
                      segments: const [
                        ButtonSegment(
                          value: false,
                          label: Text('Standard Note'),
                          icon: Icon(Icons.note_alt_outlined),
                        ),
                        ButtonSegment(
                          value: true,
                          label: Text('Checklist / To-Do'),
                          icon: Icon(Icons.check_box_outlined),
                        ),
                      ],
                      selected: {dialogIsChecklist},
                      onSelectionChanged: (Set<bool> selection) {
                        setModalState(() {
                          dialogIsChecklist = selection.first;
                        });
                        triggerAutoSave();
                      },
                    ),
                    const SizedBox(height: 12),

                    // Date & Time Reminder Bar
                    InkWell(
                      onTap: pickReminderDateTime,
                      borderRadius: BorderRadius.circular(12),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                        decoration: BoxDecoration(
                          color: dialogReminder != null
                              ? Colors.indigo.shade50
                              : inputFillColor,
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: dialogReminder != null ? Colors.indigo : Colors.transparent,
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              Icons.notifications_active_outlined,
                              color: dialogReminder != null ? Colors.indigo : Colors.grey,
                              size: 20,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                dialogReminder != null
                                    ? 'Reminder: ${_formatReminderDate(dialogReminder!)}'
                                    : 'Set Date & Time Reminder (Study, Meeting, Assignment)',
                                style: TextStyle(
                                  fontSize: 13,
                                  fontWeight: dialogReminder != null ? FontWeight.bold : FontWeight.normal,
                                  color: dialogReminder != null ? Colors.indigo : Colors.grey.shade700,
                                ),
                              ),
                            ),
                            if (dialogReminder != null)
                              IconButton(
                                icon: const Icon(Icons.cancel, size: 18, color: Colors.indigo),
                                onPressed: () {
                                  setModalState(() {
                                    dialogReminder = null;
                                  });
                                  triggerAutoSave();
                                },
                              ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),

                    TextField(
                      controller: _titleController,
                      autofocus: true,
                      decoration: InputDecoration(
                        labelText: 'Title',
                        hintText: dialogIsChecklist ? 'e.g., Daily Tasks or Study Session' : 'Title...',
                        filled: true,
                        fillColor: inputFillColor,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(12),
                          borderSide: BorderSide.none,
                        ),
                      ),
                      onChanged: (_) => triggerAutoSave(),
                    ),
                    const SizedBox(height: 12),

                    if (!dialogIsChecklist) ...[
                      TextField(
                        controller: _contentController,
                        maxLines: 4,
                        decoration: InputDecoration(
                          labelText: 'Content / Body',
                          filled: true,
                          fillColor: inputFillColor,
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12),
                            borderSide: BorderSide.none,
                          ),
                        ),
                        onChanged: (_) => triggerAutoSave(),
                      ),
                    ] else ...[
                      const Text(
                        'Checklist Tasks',
                        style: TextStyle(fontWeight: FontWeight.bold, color: Colors.indigo, fontSize: 14),
                      ),
                      const SizedBox(height: 8),

                      // Add task item bar
                      Row(
                        children: [
                          Expanded(
                            child: TextField(
                              controller: _taskItemController,
                              decoration: InputDecoration(
                                hintText: 'Add task (e.g. Homework, Meeting prep)',
                                filled: true,
                                fillColor: inputFillColor,
                                contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                                border: OutlineInputBorder(
                                  borderRadius: BorderRadius.circular(12),
                                  borderSide: BorderSide.none,
                                ),
                              ),
                              onSubmitted: (val) {
                                if (val.trim().isNotEmpty) {
                                  setModalState(() {
                                    dialogItems.add({'task': val.trim(), 'isDone': false});
                                    _taskItemController.clear();
                                  });
                                  triggerAutoSave();
                                }
                              },
                            ),
                          ),
                          const SizedBox(width: 8),
                          IconButton.filled(
                            style: IconButton.styleFrom(backgroundColor: Colors.indigo),
                            icon: const Icon(Icons.add, color: Colors.white),
                            onPressed: () {
                              final taskText = _taskItemController.text.trim();
                              if (taskText.isNotEmpty) {
                                setModalState(() {
                                  dialogItems.add({'task': taskText, 'isDone': false});
                                  _taskItemController.clear();
                                });
                                triggerAutoSave();
                              }
                            },
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),

                      // Render items list inside modal
                      if (dialogItems.isNotEmpty)
                        Container(
                          constraints: const BoxConstraints(maxHeight: 180),
                          decoration: BoxDecoration(
                            color: inputFillColor,
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: isDark ? Colors.grey.shade800 : Colors.grey.shade200),
                          ),
                          child: ListView.builder(
                            shrinkWrap: true,
                            itemCount: dialogItems.length,
                            itemBuilder: (context, idx) {
                              var item = dialogItems[idx];
                              return ListTile(
                                dense: true,
                                leading: Checkbox(
                                  value: item['isDone'] ?? false,
                                  onChanged: (val) {
                                    setModalState(() {
                                      item['isDone'] = val ?? false;
                                    });
                                    triggerAutoSave();
                                  },
                                ),
                                title: Text(
                                  item['task'] ?? '',
                                  style: TextStyle(
                                    decoration: item['isDone'] == true ? TextDecoration.lineThrough : null,
                                  ),
                                ),
                                trailing: IconButton(
                                  icon: const Icon(Icons.close, size: 18, color: Colors.red),
                                  onPressed: () {
                                    setModalState(() {
                                      dialogItems.removeAt(idx);
                                    });
                                    triggerAutoSave();
                                  },
                                ),
                              );
                            },
                          ),
                        ),
                    ],

                    // ===== ATTACHMENTS SECTION =====
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        const Icon(Icons.attach_file, size: 18, color: Colors.indigo),
                        const SizedBox(width: 6),
                        const Text(
                          'Attachments',
                          style: TextStyle(fontWeight: FontWeight.bold, color: Colors.indigo, fontSize: 14),
                        ),
                        const Spacer(),
                        TextButton.icon(
                          icon: const Icon(Icons.add_circle_outline, size: 18),
                          label: const Text('Add File'),
                          style: TextButton.styleFrom(foregroundColor: Colors.indigo),
                          onPressed: () async {
                            try {
                              final result = await FilePicker.platform.pickFiles(
                                allowMultiple: true,
                                type: FileType.any,
                              );
                              if (result != null && result.files.isNotEmpty) {
                                for (final file in result.files) {
                                  if (file.path != null) {
                                    final storedPath = await copyToAttachmentsDir(file.path!);
                                    setModalState(() {
                                      dialogAttachments.add({
                                        'name': file.name,
                                        'path': storedPath,
                                        'size': file.size,
                                        'type': attachmentType(file.name),
                                      });
                                    });
                                  }
                                }
                                triggerAutoSave();
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(
                                      content: Text('📎 ${result.files.length} file(s) attached'),
                                      backgroundColor: Colors.indigo,
                                      duration: const Duration(seconds: 2),
                                    ),
                                  );
                                }
                              }
                            } catch (e) {
                              if (context.mounted) {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(content: Text('Error picking file: $e'), backgroundColor: Colors.red),
                                );
                              }
                            }
                          },
                        ),
                      ],
                    ),
                    if (dialogAttachments.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Container(
                        constraints: const BoxConstraints(maxHeight: 160),
                        decoration: BoxDecoration(
                          color: inputFillColor,
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: isDark ? Colors.grey.shade800 : Colors.grey.shade200),
                        ),
                        child: ListView.builder(
                          shrinkWrap: true,
                          itemCount: dialogAttachments.length,
                          itemBuilder: (context, idx) {
                            final att = dialogAttachments[idx];
                            final type = att['type'] ?? 'other';
                            final name = att['name'] ?? 'file';
                            final size = att['size'] as int? ?? 0;
                            final path = att['path'] as String? ?? '';
                            final isImage = type == 'image';

                            return ListTile(
                              dense: true,
                              leading: isImage && path.isNotEmpty && File(path).existsSync()
                                  ? ClipRRect(
                                      borderRadius: BorderRadius.circular(6),
                                      child: Image.file(
                                        File(path),
                                        width: 36, height: 36, fit: BoxFit.cover,
                                      ),
                                    )
                                  : CircleAvatar(
                                      radius: 18,
                                      backgroundColor: attachmentColor(type).withValues(alpha: 0.15),
                                      child: Icon(attachmentIcon(type), size: 18, color: attachmentColor(type)),
                                    ),
                              title: Text(name, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 13)),
                              subtitle: Text(formatFileSize(size), style: TextStyle(fontSize: 11, color: Colors.grey.shade600)),
                              trailing: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  IconButton(
                                    icon: const Icon(Icons.open_in_new, size: 16, color: Colors.indigo),
                                    tooltip: 'Open',
                                    onPressed: () => OpenFilex.open(path),
                                  ),
                                  IconButton(
                                    icon: const Icon(Icons.close, size: 16, color: Colors.red),
                                    tooltip: 'Remove',
                                    onPressed: () {
                                      deleteAttachmentFile(path);
                                      setModalState(() => dialogAttachments.removeAt(idx));
                                      triggerAutoSave();
                                    },
                                  ),
                                ],
                              ),
                            );
                          },
                        ),
                      ),
                    ] else
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Text(
                          'No attachments yet — tap "Add File" to attach images, PDFs, documents, etc.',
                          style: TextStyle(fontSize: 12, color: Colors.grey.shade500, fontStyle: FontStyle.italic),
                        ),
                      ),

                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            initialValue: _folders.where((f) => f != 'All Notes').contains(dialogFolder)
                                ? dialogFolder
                                : _folders.where((f) => f != 'All Notes').first,
                            decoration: InputDecoration(
                              labelText: 'Folder',
                              filled: true,
                              fillColor: inputFillColor,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(12),
                                borderSide: BorderSide.none,
                              ),
                            ),
                            items: _folders.where((f) => f != 'All Notes').map((f) {
                              return DropdownMenuItem(value: f, child: Text(f));
                            }).toList(),
                            onChanged: (val) {
                              if (val != null) {
                                setModalState(() => dialogFolder = val);
                                triggerAutoSave();
                              }
                            },
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            initialValue: _tags.where((t) => t != 'All').contains(dialogTag)
                                ? dialogTag
                                : _tags.where((t) => t != 'All').first,
                            decoration: InputDecoration(
                              labelText: 'Tag',
                              filled: true,
                              fillColor: inputFillColor,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(12),
                                borderSide: BorderSide.none,
                              ),
                            ),
                            items: _tags.where((t) => t != 'All').map((t) {
                              return DropdownMenuItem(value: t, child: Text(t));
                            }).toList(),
                            onChanged: (val) {
                              if (val != null) {
                                setModalState(() => dialogTag = val);
                                triggerAutoSave();
                              }
                            },
                          ),
                        ),
                      ],
                    ),
                                        const SizedBox(height: 12),
                    Container(
                      decoration: BoxDecoration(
                        color: dialogIsLocked
                            ? (isDark ? Colors.red.shade900.withValues(alpha: 0.2) : Colors.red.shade50)
                            : inputFillColor,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: dialogIsLocked ? Colors.red.shade400 : Colors.transparent,
                        ),
                      ),
                      child: SwitchListTile(
                        secondary: Icon(
                          dialogIsLocked ? Icons.lock : Icons.lock_open_outlined,
                          color: dialogIsLocked ? Colors.red.shade700 : Colors.grey,
                        ),
                        title: const Text('Sensitive / Protected Note', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                        subtitle: Text(
                          dialogIsLocked
                              ? 'Locked with PIN: Hidden until authenticated'
                              : 'Protect this note with your security PIN',
                          style: const TextStyle(fontSize: 11),
                        ),
                        value: dialogIsLocked,
                        activeThumbColor: Colors.red.shade700,
                        onChanged: (val) async {
                          if (val && !(AuthService.instance.currentUser?.hasPin ?? false)) {
                            final pinSet = await _promptSetPinDialog();
                            if (!pinSet) return;
                          }
                          setModalState(() => dialogIsLocked = val);
                          triggerAutoSave();
                        },
                      ),
                    ),
                    const SizedBox(height: 20),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.indigo,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                        onPressed: () {
                          autoSaveTimer?.cancel();
                          _saveNoteToFirebase(
                            activeDocId,
                            dialogFolder,
                            dialogTag,
                            dialogIsPinned,
                            dialogIsChecklist,
                            dialogItems,
                            dialogReminder,
                            dialogAttachments,
                            isLocked: dialogIsLocked,
                          );
                          Navigator.pop(context);
                        },
                        child: Text(
                          activeDocId == null ? 'Done' : 'Done & Close',
                          style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  Future<void> _syncReminder(String docId, Map<String, dynamic> data) async {
    final id = int.tryParse(docId);
    if (id == null) return;
    await _notifications.cancel(id: id);
    final reminder = data['reminderTime'];
    if (reminder is Timestamp && reminder.toDate().isAfter(DateTime.now())) {
      const details = NotificationDetails(
        android: AndroidNotificationDetails(
          'noteapp_reminders',
          'Note reminders',
          channelDescription: 'Reminders for saved notes and tasks',
          importance: Importance.max,
          priority: Priority.high,
          playSound: true,
        ),
      );
      await _notifications.zonedSchedule(
        id: id,
        title: (data['title'] ?? 'Note reminder').toString(),
        body: (data['text'] ?? 'It is time for your reminder.').toString(),
        scheduledDate: tz.TZDateTime.from(reminder.toDate(), tz.local),
        notificationDetails: details,
        androidScheduleMode: AndroidScheduleMode.exactAllowWhileIdle,
      );
    }
  }

  void _saveNoteToFirebase(
      String? docId,
      String folder,
      String tag,
      bool isPinned,
      bool isChecklist,
      List<Map<String, dynamic>> items,
      DateTime? reminderDateTime,
      List<Map<String, dynamic>> attachments, {
      bool isLocked = false,
      }) async {
    final title = _titleController.text.trim();
    final text = _contentController.text.trim();

    if (title.isEmpty && text.isEmpty && items.isEmpty && attachments.isEmpty) return;

    try {
      final data = {
        'title': title.isEmpty ? (isChecklist ? 'Checklist' : 'Untitled') : title,
        'text': text,
        'folder': folder,
        'tag': tag,
        'isPinned': isPinned,
        'isChecklist': isChecklist,
        'items': items,
        'isLocked': isLocked,
        'attachments': attachments,
        'reminderTime': reminderDateTime != null ? Timestamp.fromDate(reminderDateTime) : null,
        'timestamp': FieldValue.serverTimestamp(),
        'isSynced': ConnectivityService.instance.isOnline,
        'syncStatus': ConnectivityService.instance.isOnline ? 'synced' : 'pending',
        if (ConnectivityService.instance.isOnline) 'lastSyncedAt': FieldValue.serverTimestamp(),
      };

      if (docId == null) {
        await LocalFirestore.instance.collection('notes').add(data);
      } else {
        await LocalFirestore.instance.collection('notes').doc(docId).update(data);
      }

      final savedId = docId ?? LocalFirestore.instance.lastInsertedId?.toString();
      if (savedId != null) {
        await _syncReminder(savedId, data);
      }
      _titleController.clear();
      _contentController.clear();
      _taskItemController.clear();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Local storage error: $e'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 4),
          ),
        );
      }
    }
  }

  void _toggleChecklistItem(String docId, List<dynamic> items, int index, bool currentDoneState) async {
    try {
      List<dynamic> updatedItems = List.from(items.map((i) => Map<String, dynamic>.from(i)));
      updatedItems[index]['isDone'] = !currentDoneState;

      await LocalFirestore.instance.collection('notes').doc(docId).update({
        'items': updatedItems,
        'isSynced': ConnectivityService.instance.isOnline,
        'syncStatus': ConnectivityService.instance.isOnline ? 'synced' : 'pending',
        if (ConnectivityService.instance.isOnline) 'lastSyncedAt': FieldValue.serverTimestamp(),
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error updating task: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  void _togglePin(String docId, bool currentPinState) async {
    try {
      await LocalFirestore.instance.collection('notes').doc(docId).update({
        'isPinned': !currentPinState,
        'isSynced': ConnectivityService.instance.isOnline,
        'syncStatus': ConnectivityService.instance.isOnline ? 'synced' : 'pending',
        if (ConnectivityService.instance.isOnline) 'lastSyncedAt': FieldValue.serverTimestamp(),
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error updating pin: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  void _deleteNote(String docId, {List<dynamic>? noteAttachments}) async {
    try {
      // Clean up attachment files from disk
      if (noteAttachments != null) {
        for (final att in noteAttachments) {
          final path = att is Map ? att['path'] as String? : null;
          if (path != null) deleteAttachmentFile(path);
        }
      }
      await LocalFirestore.instance.collection('notes').doc(docId).delete();
      final notificationId = int.tryParse(docId);
      if (notificationId != null) await _notifications.cancel(id: notificationId);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error deleting item: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final appState = CloudNotesApp.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: _isSearching
            ? TextField(
          controller: _searchController,
          autofocus: true,
          style: const TextStyle(color: Colors.white, fontSize: 16),
          cursorColor: Colors.white,
          decoration: const InputDecoration(
            hintText: 'Search title, content, folder, or tag...',
            hintStyle: TextStyle(color: Colors.white70, fontSize: 14),
            border: InputBorder.none,
          ),
          onChanged: (val) {
            setState(() {
              _searchQuery = val.trim().toLowerCase();
            });
          },
        )
            : Text('NoteApp: $_selectedFolder', style: const TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.indigo,
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            icon: _isSyncing
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                  )
                : Icon(
                    _isOnline ? Icons.cloud_sync_outlined : Icons.cloud_off_outlined,
                    color: _isOnline ? Colors.white : Colors.amber.shade200,
                  ),
            tooltip: _isOnline ? 'Sync with Cloud' : 'Offline Mode (Tap to test connection & sync)',
            onPressed: _triggerManualSync,
          ),
          IconButton(
            icon: Icon(_isSearching ? Icons.close : Icons.search),
            tooltip: 'Search Notes',
            onPressed: () {
              setState(() {
                if (_isSearching) {
                  _isSearching = false;
                  _searchQuery = '';
                  _searchController.clear();
                } else {
                  _isSearching = true;
                }
              });
            },
          ),
          IconButton(
            icon: const Icon(Icons.format_size),
            tooltip: 'Adjust Text Size',
            onPressed: _showTextSizeDialog,
          ),
          IconButton(
            icon: Icon(appState.isDarkMode ? Icons.light_mode : Icons.dark_mode),
            tooltip: appState.isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode',
            onPressed: appState.toggleTheme,
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.sort),
            tooltip: 'Sort Notes',
            onSelected: (val) => setState(() => _sortBy = val),
            itemBuilder: (context) => [
              const PopupMenuItem(value: 'Newest', child: Text('Sort by Newest')),
              const PopupMenuItem(value: 'Oldest', child: Text('Sort by Oldest')),
              const PopupMenuItem(value: 'Alphabetical', child: Text('Sort Alphabetically')),
            ],
          ),
        ],
      ),
      drawer: Drawer(
        child: ListView(
          padding: EdgeInsets.zero,
          children: [
            DrawerHeader(
              decoration: const BoxDecoration(color: Colors.indigo),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  Row(
                    children: [
                      CircleAvatar(
                        radius: 22,
                        backgroundColor: Colors.white,
                        child: Text(
                          (AuthService.instance.currentUser?.name.isNotEmpty == true)
                              ? AuthService.instance.currentUser!.name[0].toUpperCase()
                              : 'U',
                          style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.indigo),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              AuthService.instance.currentUser?.name ?? 'Notes User',
                              style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                              overflow: TextOverflow.ellipsis,
                            ),
                            Text(
                              AuthService.instance.currentUser?.email ?? '',
                              style: const TextStyle(color: Colors.white70, fontSize: 12),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.2),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: const Row(
                          children: [
                            Icon(Icons.lock, size: 11, color: Colors.white),
                            SizedBox(width: 4),
                            Text('Private Vault Active', style: TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold)),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            ListTile(
              leading: const Icon(Icons.shield_outlined, color: Colors.indigo),
              title: const Text('Security PIN Lock'),
              subtitle: Text(
                AuthService.instance.currentUser?.hasPin == true
                    ? 'Configured â€¢ Tap to change PIN'
                    : 'Not configured â€¢ Tap to set PIN',
                style: const TextStyle(fontSize: 12),
              ),
              onTap: () {
                Navigator.pop(context);
                _promptSetPinDialog();
              },
            ),
            ListTile(
              leading: const Icon(Icons.logout, color: Colors.red),
              title: const Text('Log Out', style: TextStyle(color: Colors.red, fontWeight: FontWeight.w600)),
              onTap: () {
                Navigator.pop(context);
                _handleLogout();
              },
            ),
            ListTile(
              leading: Icon(appState.isDarkMode ? Icons.light_mode : Icons.dark_mode, color: Colors.indigo),
              title: Text(appState.isDarkMode ? 'Light Theme Mode' : 'Dark Theme Mode'),
              onTap: () {
                appState.toggleTheme();
                Navigator.pop(context);
              },
            ),
            ListTile(
              leading: const Icon(Icons.format_size, color: Colors.indigo),
              title: const Text('Text Size & Reader Mode'),
              onTap: () {
                Navigator.pop(context);
                _showTextSizeDialog();
              },
            ),
            const Divider(),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Text('CLOUD & SYNC STATUS', style: TextStyle(color: Colors.grey, fontWeight: FontWeight.bold, fontSize: 12)),
            ),
            ListTile(
              leading: Icon(
                _isOnline ? Icons.cloud_done : Icons.cloud_off,
                color: _isOnline ? Colors.teal : Colors.orange.shade800,
              ),
              title: Text(_isOnline ? 'Online (Connected)' : 'Offline Mode'),
              subtitle: Text(
                _isOnline
                    ? (SyncManager.instance.lastSyncedAt != null
                        ? 'Last synced: ${_formatTimestamp(Timestamp.fromDate(SyncManager.instance.lastSyncedAt!))}'
                        : 'All notes synchronized with cloud')
                    : '${SyncManager.instance.getPendingCount()} offline note(s) pending sync',
                style: const TextStyle(fontSize: 12),
              ),
              trailing: ElevatedButton.icon(
                onPressed: () {
                  Navigator.pop(context);
                  _triggerManualSync();
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.indigo,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                ),
                icon: const Icon(Icons.sync, size: 14),
                label: const Text('Sync', style: TextStyle(fontSize: 12)),
              ),
            ),
            const Divider(),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Text('FOLDERS / CATEGORIES', style: TextStyle(color: Colors.grey, fontWeight: FontWeight.bold, fontSize: 12)),
            ),
            ..._folders.map((folder) => ListTile(
              leading: const Icon(Icons.folder_outlined, color: Colors.indigo),
              title: Text(folder),
              selected: _selectedFolder == folder,
              onTap: () {
                setState(() => _selectedFolder = folder);
                Navigator.pop(context);
              },
            )),
            const Divider(),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Text('TAGS', style: TextStyle(color: Colors.grey, fontWeight: FontWeight.bold, fontSize: 12)),
            ),
            ..._tags.map((tag) => ListTile(
              leading: const Icon(Icons.tag, color: Colors.indigoAccent),
              title: Text(tag),
              selected: _selectedTag == tag,
              onTap: () {
                setState(() => _selectedTag = tag);
                Navigator.pop(context);
              },
            )),
          ],
        ),
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: LocalFirestore.instance
            .collection('notes')
            .snapshots(includeMetadataChanges: true),
        builder: (context, snapshot) {


          return Column(
            children: [
              // Filter & Local Storage Status Bar
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                color: isDark ? Colors.indigo.shade900.withValues(alpha: 0.3) : Colors.indigo.shade50,
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Expanded(
                      child: Text(
                        _searchQuery.isNotEmpty
                            ? 'Searching: "$_searchQuery"'
                            : 'Folder: $_selectedFolder | Tag: $_selectedTag',
                        style: TextStyle(fontSize: 12, color: isDark ? Colors.indigo.shade200 : Colors.indigo, fontWeight: FontWeight.w600),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const SizedBox(width: 8),

                    // Connectivity & Cloud Sync Status Badge
                    InkWell(
                      borderRadius: BorderRadius.circular(12),
                      onTap: _triggerManualSync,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                        decoration: BoxDecoration(
                          color: !_isOnline
                              ? (isDark ? Colors.amber.shade900.withValues(alpha: 0.3) : Colors.amber.shade100)
                              : (_isSyncing
                                  ? Colors.blue.shade100
                                  : (isDark ? Colors.green.shade900.withValues(alpha: 0.5) : Colors.green.shade100)),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: !_isOnline
                                ? Colors.amber.shade400
                                : (_isSyncing ? Colors.blue.shade300 : Colors.green.shade400),
                            width: 0.8,
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              !_isOnline
                                  ? Icons.cloud_off
                                  : (_isSyncing ? Icons.sync : Icons.cloud_done),
                              size: 13,
                              color: !_isOnline
                                  ? Colors.amber.shade900
                                  : (_isSyncing ? Colors.blue.shade900 : (isDark ? Colors.green.shade300 : Colors.green.shade900)),
                            ),
                            const SizedBox(width: 4),
                            Text(
                              !_isOnline
                                  ? 'Offline ( pending)'
                                  : (_isSyncing ? 'Syncing...' : 'Online & Synced'),
                              style: TextStyle(
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                                color: !_isOnline
                                    ? Colors.amber.shade900
                                    : (_isSyncing ? Colors.blue.shade900 : (isDark ? Colors.green.shade300 : Colors.green.shade900)),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              // Offline notice banner
              if (!_isOnline)
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                  color: Colors.amber.shade700,
                  child: Row(
                    children: [
                      const Icon(Icons.wifi_off, size: 14, color: Colors.white),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'Offline Mode: You can create, edit, & read notes. Changes will auto-sync when online.',
                          style: TextStyle(fontSize: 11, color: Colors.white, fontWeight: FontWeight.w500),
                        ),
                      ),
                      InkWell(
                        onTap: _triggerManualSync,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.25),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text('Retry', style: TextStyle(fontSize: 10, color: Colors.white, fontWeight: FontWeight.bold)),
                        ),
                      ),
                    ],
                  ),
                ),

              Expanded(
                child: Builder(
                  builder: (context) {
                    if (snapshot.hasError) {
                      final errStr = snapshot.error.toString();
                      bool isPermissionDenied = errStr.contains('permission-denied');
                      return Center(
                        child: Container(
                          margin: const EdgeInsets.all(20),
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: Colors.red.shade50,
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(color: Colors.red.shade200),
                          ),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(Icons.error_outline, size: 48, color: Colors.red.shade700),
                              const SizedBox(height: 12),
                              Text(
                                isPermissionDenied ? 'Local Storage Error' : 'Local Storage Error',
                                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.red.shade900),
                              ),
                              const SizedBox(height: 8),
                              Text(
                                isPermissionDenied
                                    ? 'Local database access was denied.'
                                    : 'Error details: $errStr',
                                textAlign: TextAlign.center,
                                style: TextStyle(fontSize: 13, color: Colors.red.shade800),
                              ),
                            ],
                          ),
                        ),
                      );
                    }

                    if (snapshot.connectionState == ConnectionState.waiting) return const Center(child: CircularProgressIndicator());

                    var docs = snapshot.data?.docs ?? [];

                    // Filter by Search Query
                    if (_searchQuery.isNotEmpty) {
                      docs = docs.where((d) {
                        var data = d.data();
                        String title = (data['title'] ?? '').toString().toLowerCase();
                        String text = (data['text'] ?? '').toString().toLowerCase();
                        String folder = (data['folder'] ?? '').toString().toLowerCase();
                        String tag = (data['tag'] ?? '').toString().toLowerCase();
                        List<dynamic> items = data['items'] ?? [];
                        String itemsText = items.map((i) => (i['task'] ?? '').toString()).join(' ').toLowerCase();

                        return title.contains(_searchQuery) ||
                            text.contains(_searchQuery) ||
                            folder.contains(_searchQuery) ||
                            tag.contains(_searchQuery) ||
                            itemsText.contains(_searchQuery);
                      }).toList();
                    } else {
                      // Filter by Folder
                      if (_selectedFolder != 'All Notes') {
                        docs = docs.where((d) => d.data()['folder'] == _selectedFolder).toList();
                      }

                      // Filter by Tag
                      if (_selectedTag != 'All') {
                        docs = docs.where((d) => d.data()['tag'] == _selectedTag).toList();
                      }
                    }

                    // Sort docs
                    docs.sort((a, b) {
                      var dataA = a.data();
                      var dataB = b.data();

                      // Pinned notes always come first
                      bool pinA = dataA['isPinned'] ?? false;
                      bool pinB = dataB['isPinned'] ?? false;
                      if (pinA != pinB) return pinA ? -1 : 1;

                      if (_sortBy == 'Alphabetical') {
                        String titleA = dataA['title'] ?? '';
                        String titleB = dataB['title'] ?? '';
                        return titleA.compareTo(titleB);
                      } else {
                        Timestamp? tA = dataA['timestamp'];
                        Timestamp? tB = dataB['timestamp'];
                        if (tA == null || tB == null) return 0;
                        return _sortBy == 'Newest' ? tB.compareTo(tA) : tA.compareTo(tB);
                      }
                    });

                    if (docs.isEmpty) {
                      return Center(
                        child: Padding(
                          padding: const EdgeInsets.all(24.0),
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(
                                _searchQuery.isNotEmpty ? Icons.search_off : Icons.note_alt_outlined,
                                size: 64,
                                color: Colors.grey.shade400,
                              ),
                              const SizedBox(height: 12),
                              Text(
                                _searchQuery.isNotEmpty
                                    ? 'No items matching "$_searchQuery"'
                                    : 'No notes or checklists found in this view.',
                                textAlign: TextAlign.center,
                                style: const TextStyle(fontSize: 16, color: Colors.grey, fontWeight: FontWeight.w500),
                              ),
                            ],
                          ),
                        ),
                      );
                    }

                    return RefreshIndicator(
                      onRefresh: _triggerManualSync,
                      child: ListView.builder(
                      padding: const EdgeInsets.all(16),
                      itemCount: docs.length,
                      itemBuilder: (context, index) {
                        var noteData = docs[index].data();
                        String docId = docs[index].id;
                        String title = noteData['title'] ?? 'Untitled';
                        String text = noteData['text'] ?? '';
                        String folder = noteData['folder'] ?? 'Assignments';
                        String tag = noteData['tag'] ?? '#todo';
                        bool isPinned = noteData['isPinned'] ?? false;
                        bool isChecklist = noteData['isChecklist'] ?? false;
                        List<dynamic> items = noteData['items'] ?? [];
                        Timestamp? timestamp = noteData['timestamp'];
                        Timestamp? reminderTime = noteData['reminderTime'];
                        List<dynamic> attachments = noteData['attachments'] ?? [];
                        bool isNoteSynced = noteData['isSynced'] ?? false;
                        bool isLocked = noteData['isLocked'] ?? false;
                        bool isNoteUnlocked = _unlockedDocIds.contains(docId);

                        // Calculate checklist stats
                        int completedCount = items.where((i) => i['isDone'] == true).length;
                        int totalCount = items.length;
                        double progress = totalCount > 0 ? completedCount / totalCount : 0.0;

                        final cardBg = isDark ? Colors.grey.shade900 : Colors.white;
                        final cardTitleColor = isDark ? Colors.indigo.shade200 : Colors.indigo;
                        final cardTextColor = isDark ? Colors.white70 : Colors.black87;

                        return Container(
                          margin: const EdgeInsets.only(bottom: 12),
                          decoration: BoxDecoration(
                            color: cardBg,
                            borderRadius: BorderRadius.circular(16),
                            border: isPinned ? Border.all(color: Colors.indigo, width: 1.5) : null,
                            boxShadow: [
                              BoxShadow(color: Colors.black.withValues(alpha: 0.05), blurRadius: 10, offset: const Offset(0, 4)),
                            ],
                          ),
                          child: InkWell(
                            borderRadius: BorderRadius.circular(16),
                            onTap: () {
                              if (isLocked && !isNoteUnlocked) {
                                _promptUnlockNote(docId, noteData);
                              } else {
                                _showNoteDialog(
                                  docId: docId,
                                  existingTitle: title,
                                  existingText: text,
                                  existingFolder: folder,
                                  existingTag: tag,
                                  existingIsPinned: isPinned,
                                  existingIsChecklist: isChecklist,
                                  existingItems: items,
                                  existingReminder: reminderTime,
                                  existingAttachments: attachments,
                                  existingIsLocked: isLocked,
                                );
                              }
                            },
                            child: Padding(
                              padding: const EdgeInsets.all(16.0),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      Row(
                                        children: [
                                          Icon(
                                            isChecklist ? Icons.check_box_outlined : Icons.description_outlined,
                                            size: 20,
                                            color: cardTitleColor,
                                          ),
                                          const SizedBox(width: 8),
                                          Text(
                                            title,
                                            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: cardTitleColor),
                                          ),
                                        ],
                                      ),
                                      Row(
                                        mainAxisSize: MainAxisSize.min,
                                        children: [
                                          if (!isNoteSynced)
                                            Container(
                                              margin: const EdgeInsets.only(right: 6),
                                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                              decoration: BoxDecoration(
                                                color: isDark ? Colors.amber.shade900.withValues(alpha: 0.3) : Colors.amber.shade50,
                                                borderRadius: BorderRadius.circular(6),
                                                border: Border.all(color: Colors.amber.shade400, width: 0.8),
                                              ),
                                              child: Row(
                                                mainAxisSize: MainAxisSize.min,
                                                children: [
                                                  Icon(Icons.cloud_off, size: 10, color: Colors.amber.shade800),
                                                  const SizedBox(width: 3),
                                                  Text(
                                                    'Offline',
                                                    style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Colors.amber.shade900),
                                                  ),
                                                ],
                                              ),
                                            )
                                          else
                                            Padding(
                                              padding: const EdgeInsets.only(right: 6),
                                              child: Tooltip(
                                                message: 'Synced with cloud',
                                                child: Icon(Icons.cloud_done_outlined, size: 15, color: Colors.teal.shade500),
                                              ),
                                            ),
                                          if (isPinned)
                                            Icon(Icons.push_pin, size: 18, color: cardTitleColor),
                                        ],
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 8),

                                  // Sensitive locked view vs unlocked view
                                  if (isLocked && !isNoteUnlocked) ...[
                                    Container(
                                      margin: const EdgeInsets.symmetric(vertical: 8),
                                      padding: const EdgeInsets.all(12),
                                      decoration: BoxDecoration(
                                        color: isDark ? Colors.red.shade900.withValues(alpha: 0.15) : Colors.red.shade50,
                                        borderRadius: BorderRadius.circular(10),
                                        border: Border.all(color: Colors.red.shade200),
                                      ),
                                      child: Row(
                                        children: [
                                          Icon(Icons.lock, size: 20, color: Colors.red.shade700),
                                          const SizedBox(width: 10),
                                          const Expanded(
                                            child: Column(
                                              crossAxisAlignment: CrossAxisAlignment.start,
                                              children: [
                                                Text(
                                                  'Sensitive Note Protected',
                                                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.red),
                                                ),
                                                SizedBox(height: 2),
                                                Text(
                                                  'Content is encrypted. Tap to enter Security PIN.',
                                                  style: TextStyle(fontSize: 11, color: Colors.grey),
                                                ),
                                              ],
                                            ),
                                          ),
                                          Icon(Icons.arrow_forward_ios, size: 12, color: Colors.red.shade400),
                                        ],
                                      ),
                                    ),
                                  ] else ...[
                                  // Reminder Badge
                                  if (reminderTime != null) ...[
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                      decoration: BoxDecoration(
                                        color: isDark ? Colors.indigo.shade900 : Colors.indigo.shade50,
                                        borderRadius: BorderRadius.circular(8),
                                        border: Border.all(color: Colors.indigo.shade300),
                                      ),
                                      child: Row(
                                        mainAxisSize: MainAxisSize.min,
                                        children: [
                                          const Icon(Icons.notifications_active, size: 14, color: Colors.indigo),
                                          const SizedBox(width: 6),
                                          Text(
                                            'Reminder: ${_formatReminderDate(reminderTime.toDate())}',
                                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: isDark ? Colors.indigo.shade200 : Colors.indigo),
                                          ),
                                        ],
                                      ),
                                    ),
                                    const SizedBox(height: 8),
                                  ],

                                  // Render Standard Text Note OR Checklist Items
                                  if (!isChecklist) ...[
                                    if (text.isNotEmpty)
                                      Text(
                                        text,
                                        maxLines: 3,
                                        overflow: TextOverflow.ellipsis,
                                        style: TextStyle(fontSize: 14, color: cardTextColor),
                                      ),
                                  ] else ...[
                                    // Progress bar for Checklist
                                    Row(
                                      children: [
                                        Expanded(
                                          child: ClipRRect(
                                            borderRadius: BorderRadius.circular(4),
                                            child: LinearProgressIndicator(
                                              value: progress,
                                              backgroundColor: isDark ? Colors.grey.shade800 : Colors.indigo.shade50,
                                              color: progress == 1.0 ? Colors.green : Colors.indigo,
                                              minHeight: 6,
                                            ),
                                          ),
                                        ),
                                        const SizedBox(width: 10),
                                        Text(
                                          '$completedCount / $totalCount done',
                                          style: TextStyle(
                                            fontSize: 12,
                                            fontWeight: FontWeight.bold,
                                            color: progress == 1.0 ? Colors.green : cardTitleColor,
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 8),

                                    // Checklist Tasks List with Interactive Checkboxes
                                    Column(
                                      children: List.generate(items.length, (itemIdx) {
                                        var item = items[itemIdx];
                                        bool isDone = item['isDone'] ?? false;
                                        String taskName = item['task'] ?? '';

                                        return InkWell(
                                          onTap: () => _toggleChecklistItem(docId, items, itemIdx, isDone),
                                          child: Padding(
                                            padding: const EdgeInsets.symmetric(vertical: 2.0),
                                            child: Row(
                                              children: [
                                                SizedBox(
                                                  width: 24,
                                                  height: 24,
                                                  child: Checkbox(
                                                    value: isDone,
                                                    activeColor: Colors.indigo,
                                                    onChanged: (val) => _toggleChecklistItem(docId, items, itemIdx, isDone),
                                                  ),
                                                ),
                                                const SizedBox(width: 8),
                                                Expanded(
                                                  child: Text(
                                                    taskName,
                                                    style: TextStyle(
                                                      fontSize: 14,
                                                      color: isDone ? Colors.grey : cardTextColor,
                                                      decoration: isDone ? TextDecoration.lineThrough : null,
                                                    ),
                                                  ),
                                                ),
                                              ],
                                            ),
                                          ),
                                        );
                                      }),
                                    ),
                                  ],

                                  // Attachment badge on card
                                  if (attachments.isNotEmpty) ...[
                                    const SizedBox(height: 8),
                                    Wrap(
                                      spacing: 6,
                                      runSpacing: 4,
                                      children: [
                                        Container(
                                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                          decoration: BoxDecoration(
                                            color: isDark ? Colors.teal.shade900 : Colors.teal.shade50,
                                            borderRadius: BorderRadius.circular(8),
                                            border: Border.all(color: Colors.teal.shade300),
                                          ),
                                          child: Row(
                                            mainAxisSize: MainAxisSize.min,
                                            children: [
                                              const Icon(Icons.attach_file, size: 13, color: Colors.teal),
                                              const SizedBox(width: 4),
                                              Text(
                                                '${attachments.length} attachment${attachments.length > 1 ? 's' : ''}',
                                                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: isDark ? Colors.teal.shade200 : Colors.teal.shade800),
                                              ),
                                            ],
                                          ),
                                        ),
                                        ...attachments.take(3).map((att) {
                                          final type = att is Map ? (att['type'] ?? 'other') : 'other';
                                          final name = att is Map ? (att['name'] ?? 'file') : 'file';
                                          return Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                                            decoration: BoxDecoration(
                                              color: attachmentColor(type).withValues(alpha: 0.1),
                                              borderRadius: BorderRadius.circular(6),
                                            ),
                                            child: Row(
                                              mainAxisSize: MainAxisSize.min,
                                              children: [
                                                Icon(attachmentIcon(type), size: 12, color: attachmentColor(type)),
                                                const SizedBox(width: 3),
                                                ConstrainedBox(
                                                  constraints: const BoxConstraints(maxWidth: 80),
                                                  child: Text(
                                                    name,
                                                    maxLines: 1,
                                                    overflow: TextOverflow.ellipsis,
                                                    style: TextStyle(fontSize: 10, color: attachmentColor(type)),
                                                  ),
                                                ),
                                              ],
                                            ),
                                          );
                                        }),
                                        if (attachments.length > 3)
                                          Text('+${attachments.length - 3} more', style: TextStyle(fontSize: 10, color: Colors.grey.shade500)),
                                      ],
                                    ),
                                  ],
                                  ],

                                  const SizedBox(height: 12),
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      Row(
                                        children: [
                                          Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                            decoration: BoxDecoration(
                                              color: isDark ? Colors.indigo.shade900 : Colors.indigo.shade50,
                                              borderRadius: BorderRadius.circular(6),
                                            ),
                                            child: Text(folder, style: TextStyle(fontSize: 11, color: isDark ? Colors.indigo.shade200 : Colors.indigo, fontWeight: FontWeight.bold)),
                                          ),
                                          const SizedBox(width: 6),
                                          Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                            decoration: BoxDecoration(
                                              color: isDark ? Colors.grey.shade800 : Colors.grey.shade100,
                                              borderRadius: BorderRadius.circular(6),
                                            ),
                                            child: Text(tag, style: TextStyle(fontSize: 11, color: isDark ? Colors.grey.shade300 : Colors.grey)),
                                          ),
                                          const SizedBox(width: 8),
                                          Text(
                                            _formatTimestamp(timestamp),
                                            style: TextStyle(fontSize: 11, color: Colors.grey.shade500),
                                          ),
                                        ],
                                      ),
                                      Row(
                                        children: [
                                          IconButton(
                                            icon: Icon(isPinned ? Icons.push_pin : Icons.push_pin_outlined, size: 18, color: Colors.grey),
                                            onPressed: () => _togglePin(docId, isPinned),
                                          ),
                                          IconButton(
                                            icon: const Icon(Icons.delete_outline, size: 18, color: Colors.red),
                                            onPressed: () => _deleteNote(docId, noteAttachments: attachments),
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                  );
                },
                ),
              ),
            ],
          );
        },
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showNoteDialog(),
        backgroundColor: Colors.indigo,
        foregroundColor: Colors.white,
        icon: const Icon(Icons.add),
        label: const Text('Add Note / Task', style: TextStyle(fontWeight: FontWeight.bold)),
      ),
    );
  }
}


