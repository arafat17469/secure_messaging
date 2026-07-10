import base64
import io
import os
import unittest
import uuid


# app.py reads its complete security configuration at import time. Keep the
# suite deterministic, fast, and separate from the developer's local database
# and key files.
os.environ.update({
    "DATABASE_URL": "sqlite:///:memory:",
    "SECRET_KEY": "unit-test-jwt-secret-with-sufficient-entropy",
    "PRIVATE_KEY_KEK": base64.urlsafe_b64encode(b"K" * 32).decode("ascii"),
    "MESSAGE_ENCRYPTION_KEY": base64.urlsafe_b64encode(b"M" * 32).decode("ascii"),
    "PASSWORD_HASH_ITERATIONS": "10000",
    "MIN_PASSWORD_LENGTH": "8",
    "MAX_PASSWORD_LENGTH": "128",
    "PASSWORD_REQUIRE_COMPLEXITY": "False",
    "MAX_JSON_BYTES": "4096",
    "REGISTER_RATE_LIMIT": "1000",
    "LOGIN_RATE_LIMIT": "1000",
    "MESSAGE_RATE_LIMIT": "1000",
    "API_READ_RATE_LIMIT": "1000",
    "DEMO_DB_VIEW_ENABLED": "False",
    "RELAX_SECURITY_HEADERS": "False",
    "TRUST_PROXY_HEADERS": "False",
    "CORS_ALLOWED_ORIGINS": "http://localhost",
})

import bcrypt  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402

import app as secure_app  # noqa: E402


class SecureMessagingTestCase(unittest.TestCase):
    password = "correct-horse"

    @classmethod
    def tearDownClass(cls):
        with secure_app.app.app_context():
            secure_app.db.session.remove()
            secure_app.db.engine.dispose()

    def setUp(self):
        secure_app.app.config.update(TESTING=True)
        self.http = secure_app.app.test_client()
        self.socket_clients = []

        with secure_app.app.app_context():
            secure_app.db.session.remove()
            secure_app.db.drop_all()
            secure_app.db.create_all()

        secure_app.PRIVATE_KEY_STORE.clear()
        secure_app.TOKEN_BLOCKLIST.clear()
        secure_app.RATE_LIMIT_BUCKETS.clear()
        secure_app.SOCKET_USERS.clear()
        secure_app.ONLINE_USER_COUNTS.clear()

    def tearDown(self):
        for client in self.socket_clients:
            if client.is_connected():
                client.disconnect()

        with secure_app.app.app_context():
            secure_app.db.session.remove()
            secure_app.db.drop_all()

        secure_app.PRIVATE_KEY_STORE.clear()
        secure_app.TOKEN_BLOCKLIST.clear()
        secure_app.RATE_LIMIT_BUCKETS.clear()
        secure_app.SOCKET_USERS.clear()
        secure_app.ONLINE_USER_COUNTS.clear()

    def register(self, username, password=None):
        response = self.http.post(
            "/api/register",
            json={"username": username, "password": password or self.password},
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()

    def login(self, username, password=None):
        response = self.http.post(
            "/api/login",
            json={"username": username, "password": password or self.password},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def auth_get(self, path, token):
        return self.http.get(
            path,
            headers={"Authorization": f"Bearer {token}"},
        )

    def auth_post(self, path, token):
        return self.http.post(
            path,
            headers={"Authorization": f"Bearer {token}"},
        )

    def auth_post_json(self, path, token, payload):
        return self.http.post(
            path,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    def auth_delete(self, path, token, payload=None):
        return self.http.delete(
            path,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    def socket_for(self, token):
        client = secure_app.socketio.test_client(
            secure_app.app,
            flask_test_client=secure_app.app.test_client(),
        )
        self.socket_clients.append(client)
        client.emit("join", {"token": token})
        joined = self.events_named(client, "joined")
        self.assertEqual(len(joined), 1, joined)
        return client

    @staticmethod
    def events_named(client, event_name):
        return [
            event["args"][0]
            for event in client.get_received()
            if event["name"] == event_name
        ]

    def send_message(self, client, token, receiver, message, client_id):
        client.emit("send_message", {
            "token": token,
            "receiver": receiver,
            "message": message,
            "client_id": client_id,
        })
        sent = self.events_named(client, "sent_message")
        self.assertEqual(len(sent), 1, sent)
        return sent[0]

    def test_profile_photo_can_be_uploaded_and_removed(self):
        self.register("Alice")
        self.register("Bob")
        alice = self.login("Alice")
        bob = self.login("Bob")

        upload = self.http.post(
            "/api/profile/photo",
            data={"photo": (io.BytesIO(b"small-image"), "avatar.png")},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        self.assertEqual(upload.status_code, 200, upload.get_json())
        self.assertTrue(upload.get_json()["profile"]["photo"].startswith("data:image/png;base64,"))

        sync = self.auth_get("/api/sync", bob["token"])
        self.assertEqual(sync.status_code, 200, sync.get_json())
        self.assertTrue(sync.get_json()["profiles"]["Alice"]["photo"].startswith("data:image/png;base64,"))

        removed = self.auth_delete("/api/profile/photo", alice["token"])
        self.assertEqual(removed.status_code, 200, removed.get_json())
        self.assertIsNone(removed.get_json()["profile"]["photo"])

    def test_encrypted_attachment_access_and_sender_unsend(self):
        self.register("Alice")
        self.register("Bob")
        self.register("Charlie")
        alice = self.login("Alice")
        bob = self.login("Bob")
        charlie = self.login("Charlie")

        upload = self.http.post(
            "/api/messages/attachments",
            data={
                "receiver": "Bob",
                "message": "report",
                "client_id": "attachment-1",
                "file": (io.BytesIO(b"confidential attachment"), "report.txt"),
            },
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        self.assertEqual(upload.status_code, 201, upload.get_json())
        message = upload.get_json()["message"]
        self.assertEqual(message["attachment"]["filename"], "report.txt")

        download = self.auth_get(message["attachment"]["url"], bob["token"])
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, b"confidential attachment")
        forbidden = self.auth_get(message["attachment"]["url"], charlie["token"])
        self.assertEqual(forbidden.status_code, 403)

        denied = self.auth_delete(f"/api/messages/{message['message_uuid']}", bob["token"])
        self.assertEqual(denied.status_code, 403)
        unsent = self.auth_delete(f"/api/messages/{message['message_uuid']}", alice["token"])
        self.assertEqual(unsent.status_code, 200, unsent.get_json())
        self.assertTrue(unsent.get_json()["message"]["deleted"])
        self.assertEqual(self.auth_get(message["attachment"]["url"], bob["token"]).status_code, 404)

    def test_socket_forwards_call_signaling_only_to_target(self):
        self.register("Alice")
        self.register("Bob")
        alice = self.login("Alice")
        bob = self.login("Bob")
        alice_socket = self.socket_for(alice["token"])
        bob_socket = self.socket_for(bob["token"])
        alice_socket.get_received()
        bob_socket.get_received()

        alice_socket.emit("call_offer", {
            "target": "Bob",
            "call_id": "call-1",
            "mode": "audio",
            "description": {"type": "offer", "sdp": "test-offer"},
        })
        incoming = self.events_named(bob_socket, "incoming_call")
        self.assertEqual(len(incoming), 1, incoming)
        self.assertEqual(incoming[0]["from"], "Alice")

        bob_socket.emit("call_answer", {
            "target": "Alice",
            "call_id": "call-1",
            "accepted": True,
            "description": {"type": "answer", "sdp": "test-answer"},
        })
        answer = self.events_named(alice_socket, "call_answer")
        self.assertEqual(len(answer), 1, answer)
        self.assertEqual(answer[0]["from"], "Bob")

    def test_account_deletion_requires_password_and_removes_account(self):
        self.register("Alice")
        alice = self.login("Alice")
        denied = self.auth_delete(
            "/api/account",
            alice["token"],
            {"password": "wrong-password"},
        )
        self.assertEqual(denied.status_code, 403)

        deleted = self.auth_delete(
            "/api/account",
            alice["token"],
            {"password": self.password},
        )
        self.assertEqual(deleted.status_code, 200, deleted.get_json())
        login = self.http.post(
            "/api/login",
            json={"username": "Alice", "password": self.password},
        )
        self.assertEqual(login.status_code, 401)

    def test_pbkdf2_sha512_format_uses_random_salt_and_verifies(self):
        first = secure_app.hash_password(self.password)
        second = secure_app.hash_password(self.password)

        first_parts = first.split("$")
        second_parts = second.split("$")
        self.assertEqual(len(first_parts), 4)
        self.assertEqual(first_parts[0], "pbkdf2_sha512")
        self.assertEqual(int(first_parts[1]), secure_app.PASSWORD_HASH_ITERATIONS)
        self.assertEqual(len(secure_app.b64d(first_parts[2])), 16)
        self.assertEqual(len(secure_app.b64d(first_parts[3])), 64)
        self.assertNotEqual(first_parts[2], second_parts[2])
        self.assertNotEqual(first, second)
        self.assertTrue(secure_app.verify_password(self.password, first))
        self.assertFalse(secure_app.verify_password("wrong-password", first))
        self.assertNotIn(self.password, first)

    def test_legacy_bcrypt_hash_is_migrated_after_successful_login(self):
        self.register("LegacyUser")
        legacy_hash = bcrypt.hashpw(
            self.password.encode("utf-8"),
            bcrypt.gensalt(rounds=4),
        ).decode("utf-8")

        with secure_app.app.app_context():
            user = secure_app.find_user_by_username("LegacyUser")
            user.password_hash = legacy_hash
            secure_app.db.session.commit()

        login = self.login("LegacyUser")
        self.assertTrue(login["password_hash_upgraded"])

        with secure_app.app.app_context():
            user = secure_app.find_user_by_username("LegacyUser")
            self.assertTrue(user.password_hash.startswith("pbkdf2_sha512$"))
            self.assertNotEqual(user.password_hash, legacy_hash)
            self.assertTrue(
                secure_app.verify_password(self.password, user.password_hash)
            )

    def test_register_login_and_full_sync_contract(self):
        self.register("Alice")
        self.register("Bob")
        login = self.login("Alice")

        self.assertEqual(login["password_hashing"], "PBKDF2-HMAC-SHA512")
        self.assertTrue(login["full_scan_required"])
        response = self.auth_get("/api/sync", login["token"])
        self.assertEqual(response.status_code, 200, response.get_json())

        payload = response.get_json()
        self.assertEqual(payload["authenticated_as"], "Alice")
        self.assertEqual(payload["users"], ["Bob"])
        self.assertEqual(payload["messages"], [])
        self.assertEqual(payload["scan"]["total"], 0)
        self.assertEqual(payload["scan"]["verified"], 0)
        self.assertEqual(payload["scan"]["failed"], 0)
        self.assertEqual(payload["scan"]["status"], "passed")
        self.assertTrue(payload["signing_key_ready"])
        self.assertEqual(
            payload["security"]["password_hashing"],
            "PBKDF2-HMAC-SHA512",
        )
        self.assertEqual(self.http.get("/api/sync").status_code, 401)

        with secure_app.app.app_context():
            alice = secure_app.find_user_by_username("Alice")
            self.assertTrue(alice.password_hash.startswith("pbkdf2_sha512$"))
            self.assertNotEqual(alice.rsa_public_key, "pending")
            self.assertIsNotNone(alice.active_signing_key_id)
            self.assertEqual(secure_app.SigningKey.query.count(), 2)

    def test_wrapped_signing_key_reloads_after_memory_cache_is_cleared(self):
        self.register("Alice")
        self.register("Bob")

        with secure_app.app.app_context():
            alice = secure_app.find_user_by_username("Alice")
            key_id = alice.active_signing_key_id
            signing_key = secure_app.db.session.get(secure_app.SigningKey, key_id)
            public_key = signing_key.public_key
            self.assertTrue(signing_key.wrapped_private_key)
            self.assertTrue(signing_key.nonce)
            self.assertTrue(signing_key.aes_tag)

        secure_app.PRIVATE_KEY_STORE.clear()
        login = self.login("Alice")
        self.assertFalse(login["signing_key_rotated"])

        with secure_app.app.app_context():
            alice = secure_app.find_user_by_username("Alice")
            self.assertEqual(alice.active_signing_key_id, key_id)
            self.assertIn(key_id, secure_app.PRIVATE_KEY_STORE)
            restored_private = secure_app.PRIVATE_KEY_STORE[key_id]
            restored_public = (
                RSA.import_key(restored_private)
                .publickey()
                .export_key()
                .decode("utf-8")
            )
            self.assertEqual(restored_public, public_key)

        alice_socket = self.socket_for(login["token"])
        sent = self.send_message(
            alice_socket,
            login["token"],
            "Bob",
            "message after cache reload",
            "reload-1",
        )
        self.assertEqual(sent["status"], "Verified")

    def test_socket_join_and_send_creates_verified_v2_message(self):
        self.register("Alice")
        self.register("Bob")
        alice_login = self.login("Alice")
        bob_login = self.login("Bob")
        alice_socket = self.socket_for(alice_login["token"])
        bob_socket = self.socket_for(bob_login["token"])

        # Presence events from Bob joining are unrelated to message delivery.
        alice_socket.get_received()
        bob_socket.get_received()
        sent = self.send_message(
            alice_socket,
            alice_login["token"],
            "Bob",
            "hello Bob",
            "client-msg-1",
        )
        received = self.events_named(bob_socket, "receive_message")

        self.assertEqual(len(received), 1, received)
        received = received[0]
        for payload in (sent, received):
            self.assertEqual(payload["decrypted_message"], "hello Bob")
            self.assertTrue(payload["hash_ok"])
            self.assertTrue(payload["signature_ok"])
            self.assertEqual(payload["status"], "Verified")
            self.assertEqual(payload["security_version"], 2)
            self.assertTrue(payload["metadata_bound"])
            self.assertEqual(payload["client_id"], "client-msg-1")

        self.assertEqual(sent["direction"], "sent")
        self.assertEqual(sent["delivery_status"], "delivered")
        self.assertEqual(received["direction"], "received")

        with secure_app.app.app_context():
            message = secure_app.Message.query.one()
            self.assertEqual(message.security_version, 2)
            self.assertIsNotNone(message.signing_key_id)
            self.assertNotEqual(message.encrypted_message, "hello Bob")
            decrypted, hash_ok, signature_ok, status = (
                secure_app.decrypt_and_verify_message(message)
            )
            self.assertEqual(decrypted, "hello Bob")
            self.assertTrue(hash_ok)
            self.assertTrue(signature_ok)
            self.assertEqual(status, "Verified")

    def test_sync_quarantines_metadata_ciphertext_and_hash_tampering(self):
        for username in ("Alice", "Bob"):
            self.register(username)
        alice_login = self.login("Alice")
        bob_login = self.login("Bob")
        alice_socket = self.socket_for(alice_login["token"])

        for index, text in enumerate((
            "metadata target",
            "ciphertext target",
            "hash target",
        ), start=1):
            self.send_message(
                alice_socket,
                alice_login["token"],
                "Bob",
                text,
                f"tamper-{index}",
            )

        with secure_app.app.app_context():
            messages = secure_app.Message.query.order_by(
                secure_app.Message.id.asc()
            ).all()

            messages[0].message_uuid = str(uuid.uuid4())

            ciphertext = bytearray(secure_app.b64d(messages[1].encrypted_message))
            ciphertext[0] ^= 1
            messages[1].encrypted_message = secure_app.b64e(bytes(ciphertext))

            messages[2].plaintext_sha512_hash = "0" * 128
            secure_app.db.session.commit()

        response = self.auth_get("/api/sync", bob_login["token"])
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["scan"]["total"], 3)
        self.assertEqual(payload["scan"]["verified"], 0)
        self.assertEqual(payload["scan"]["failed"], 3)
        self.assertEqual(payload["scan"]["status"], "warning")

        messages = payload["messages"]
        self.assertEqual(len(messages), 3)
        self.assertTrue(all(item["decrypted_message"] is None for item in messages))
        self.assertIn("Digital signature invalid", messages[0]["status"])
        self.assertIn("Digital signature invalid", messages[1]["status"])
        self.assertIn("content quarantined", messages[2]["status"])
        self.assertFalse(messages[2]["hash_ok"])
        self.assertTrue(messages[2]["signature_ok"])

    def test_logout_disconnects_socket_and_prevents_private_receipt(self):
        self.register("Alice")
        self.register("Bob")
        alice_login = self.login("Alice")
        bob_login = self.login("Bob")
        alice_socket = self.socket_for(alice_login["token"])
        bob_socket = self.socket_for(bob_login["token"])
        alice_socket.get_received()
        bob_socket.get_received()

        logout = self.auth_post("/api/logout", alice_login["token"])
        self.assertEqual(logout.status_code, 200, logout.get_json())
        self.assertFalse(alice_socket.is_connected())
        self.assertEqual(
            self.auth_get("/api/sync", alice_login["token"]).status_code,
            401,
        )
        self.assertEqual(secure_app.authenticated_socket_ids("Alice"), [])

        sent = self.send_message(
            bob_socket,
            bob_login["token"],
            "Alice",
            "stored while Alice is logged out",
            "post-logout-1",
        )
        self.assertEqual(sent["delivery_status"], "stored")

        with secure_app.app.app_context():
            self.assertEqual(secure_app.RevokedToken.query.count(), 1)
            self.assertEqual(secure_app.Message.query.count(), 1)

        fresh_alice = self.login("Alice")
        sync = self.auth_get("/api/sync", fresh_alice["token"]).get_json()
        self.assertEqual(sync["scan"]["verified"], 1)
        self.assertEqual(
            sync["messages"][0]["decrypted_message"],
            "stored while Alice is logged out",
        )

    def test_http_send_stores_message_when_receiver_is_offline(self):
        self.register("Alice")
        self.register("Bob")
        alice_login = self.login("Alice")

        response = self.auth_post_json(
            "/api/messages",
            alice_login["token"],
            {
                "receiver": "Bob",
                "message": "stored without Bob online",
                "client_id": "http-offline-1",
            },
        )

        self.assertEqual(response.status_code, 201, response.get_json())
        payload = response.get_json()["message"]
        self.assertEqual(payload["decrypted_message"], "stored without Bob online")
        self.assertEqual(payload["delivery_status"], "stored")
        self.assertEqual(payload["direction"], "sent")
        self.assertEqual(payload["client_id"], "http-offline-1")
        self.assertTrue(payload["hash_ok"])
        self.assertTrue(payload["signature_ok"])

        bob_login = self.login("Bob")
        sync = self.auth_get("/api/sync", bob_login["token"]).get_json()
        self.assertEqual(sync["scan"]["verified"], 1)
        self.assertEqual(sync["messages"][0]["direction"], "received")
        self.assertEqual(
            sync["messages"][0]["decrypted_message"],
            "stored without Bob online",
        )

    def test_debug_apis_are_disabled_by_default(self):
        self.register("Alice")
        token = self.login("Alice")["token"]

        users = self.auth_get("/api/debug/users", token)
        messages = self.auth_get("/api/debug/messages", token)
        self.assertEqual(users.status_code, 403, users.get_json())
        self.assertEqual(messages.status_code, 403, messages.get_json())

    def test_http_and_socket_payload_limits_share_configuration(self):
        self.assertEqual(secure_app.MAX_JSON_BYTES, 4096)
        self.assertEqual(secure_app.SOCKET_MAX_HTTP_BUFFER_SIZE, 4096)
        self.assertEqual(
            secure_app.socketio.server.eio.max_http_buffer_size,
            secure_app.MAX_JSON_BYTES,
        )

        oversized = self.http.post(
            "/api/register",
            data=b"x" * (secure_app.MAX_JSON_BYTES + 1),
            content_type="application/json",
        )
        self.assertEqual(oversized.status_code, 413, oversized.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
