#!/usr/bin/env python3
"""
Banking Security Game Server
Hệ thống mô phỏng bảo mật ngân hàng với AES, RSA, SHA
"""

import json
import hashlib
import secrets
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@dataclass
class Transaction:
    """Cấu trúc giao dịch ngân hàng"""
    id: str
    from_account: str
    to_account: str
    amount: float
    timestamp: str
    message: str = ""
    
@dataclass
class GameSession:
    """Phiên chơi game"""
    session_id: str
    player_name: str
    level: int
    score: int
    transactions_processed: int
    start_time: str

class CryptographyManager:
    """Quản lý các thuật toán mã hóa"""
    
    def __init__(self):
        # Tạo khóa RSA cho xác thực
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
    def generate_aes_key(self) -> bytes:
        """Tạo khóa AES 256-bit"""
        return secrets.token_bytes(32)
    
    def aes_encrypt(self, data: str, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Mã hóa AES với GCM mode"""
        iv = secrets.token_bytes(12)  # 96-bit IV cho GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return ciphertext, iv, encryptor.tag
    
    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> str:
        """Giải mã AES"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    
    def rsa_sign(self, message: str) -> bytes:
        """Tạo chữ ký RSA"""
        signature = self.rsa_private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def rsa_verify(self, message: str, signature: bytes) -> bool:
        """Xác thực chữ ký RSA"""
        try:
            self.rsa_public_key.verify(
                signature,
message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def sha256_hash(self, data: str) -> str:
        """Tạo SHA-256 hash"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def get_public_key_pem(self) -> str:
        """Lấy public key dạng PEM"""
        pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

class GameEngine:
    """Engine chính của game"""
    
    def __init__(self):
        self.crypto_manager = CryptographyManager()
        self.sessions: Dict[str, GameSession] = {}
        self.transaction_pool: List[Transaction] = []
        self.level_configs = {
            1: {"transaction_count": 3, "time_limit": 300, "base_score": 100},
            2: {"transaction_count": 5, "time_limit": 240, "base_score": 150},
            3: {"transaction_count": 8, "time_limit": 180, "base_score": 200}
        }
        self._generate_sample_transactions()
    
    def _generate_sample_transactions(self):
        """Tạo giao dịch mẫu"""
        sample_data = [
            ("ACC001", "ACC002", 1000000, "Chuyển khoản lương"),
            ("ACC003", "ACC004", 500000, "Thanh toán hóa đơn"),
            ("ACC005", "ACC006", 2000000, "Mua sắm online"),
            ("ACC007", "ACC008", 750000, "Chuyển tiền gia đình"),
            ("ACC009", "ACC010", 1200000, "Đầu tư chứng khoán"),
            ("ACC011", "ACC012", 300000, "Thanh toán dịch vụ"),
            ("ACC013", "ACC014", 900000, "Mua bảo hiểm"),
            ("ACC015", "ACC016", 1500000, "Gửi tiết kiệm")
        ]
        
        for i, (from_acc, to_acc, amount, msg) in enumerate(sample_data):
            transaction = Transaction(
                id=f"TXN{i+1:03d}",
                from_account=from_acc,
                to_account=to_acc,
                amount=amount,
                timestamp=datetime.now().isoformat(),
                message=msg
            )
            self.transaction_pool.append(transaction)
    
    def create_session(self, player_name: str) -> str:
        """Tạo phiên chơi mới"""
        session_id = secrets.token_urlsafe(16)
        session = GameSession(
            session_id=session_id,
            player_name=player_name,
            level=1,
            score=0,
            transactions_processed=0,
            start_time=datetime.now().isoformat()
        )
        self.sessions[session_id] = session
        return session_id
    
    def get_session(self, session_id: str) -> Optional[GameSession]:
        """Lấy thông tin phiên"""
        return self.sessions.get(session_id)

    def get_transactions_for_level(self, level: int) -> List[Transaction]:
        """Lấy giao dịch theo level"""
        config = self.level_configs[level]
        count = config["transaction_count"]
        return self.transaction_pool[:count]

    def process_transaction_security(self, transaction: Transaction) -> Dict:
        """Xử lý bảo mật giao dịch"""
        # Tạo dữ liệu giao dịch
        transaction_data = f"{transaction.id}|{transaction.from_account}|{transaction.to_account}|{transaction.amount}|{transaction.timestamp}"
        
        # 1. Mã hóa AES
        aes_key = self.crypto_manager.generate_aes_key()
        ciphertext, iv, tag = self.crypto_manager.aes_encrypt(transaction_data, aes_key)
        
        # 2. Tạo chữ ký RSA
        signature = self.crypto_manager.rsa_sign(transaction_data)
        
        # 3. Tạo SHA hash
        hash_value = self.crypto_manager.sha256_hash(transaction_data)
        
        return {
            "transaction_id": transaction.id,
            "original_data": transaction_data,
            "aes_encrypted": ciphertext.hex(),
            "aes_key": aes_key.hex(),
            "aes_iv": iv.hex(),
            "aes_tag": tag.hex(),
            "rsa_signature": signature.hex(),
            "sha256_hash": hash_value,
            "public_key": self.crypto_manager.get_public_key_pem()
        }

    def verify_security_steps(self, session_id: str, transaction_id: str, 
                            player_answers: Dict) -> Dict:
        """Kiểm tra các bước bảo mật do người chơi thực hiện"""
        session = self.get_session(session_id)
        if not session:
            return {"error": "Phiên không hợp lệ"}
        
        # Tìm giao dịch
        transaction = None
        for txn in self.transaction_pool:
            if txn.id == transaction_id:
                transaction = txn
                break
        
        if not transaction:
            return {"error": "Giao dịch không tồn tại"}
        
        # Dữ liệu gốc để kiểm tra
        transaction_data = f"{transaction.id}|{transaction.from_account}|{transaction.to_account}|{transaction.amount}|{transaction.timestamp}"

        results = {
            "aes_correct": False,
            "rsa_correct": False,
            "sha_correct": False,
            "total_score": 0,
            "feedback": []
        }
        
        # --- BẮT ĐẦU SỬA LOGIC KIỂM TRA ---

        # 1. Kiểm tra AES bằng cách giải mã
        try:
            if "aes_encrypted" in player_answers and "aes_key" in player_answers and "aes_iv" in player_answers and "aes_tag" in player_answers:
                key = bytes.fromhex(player_answers['aes_key'])
                iv = bytes.fromhex(player_answers['aes_iv'])
                tag = bytes.fromhex(player_answers['aes_tag'])
                ciphertext = bytes.fromhex(player_answers['aes_encrypted'])
                
                decrypted_data = self.crypto_manager.aes_decrypt(ciphertext, key, iv, tag)
                
                if decrypted_data == transaction_data:
                    results["aes_correct"] = True
                    results["total_score"] += 30
                    results["feedback"].append("✅ Mã hóa AES thành công!")
                else:
                    results["feedback"].append("❌ Dữ liệu giải mã AES không khớp.")
            else:
                results["feedback"].append("❌ Thiếu thông tin để kiểm tra AES.")
        except Exception as e:
            results["feedback"].append(f"❌ Lỗi giải mã AES: {e}")

        # 2. Kiểm tra RSA bằng cách xác thực chữ ký
        try:
            if "rsa_signature" in player_answers:
                signature = bytes.fromhex(player_answers['rsa_signature'])
                if self.crypto_manager.rsa_verify(transaction_data, signature):
                    results["rsa_correct"] = True
                    results["total_score"] += 40
                    results["feedback"].append("✅ Chữ ký RSA hợp lệ!")
                else:
                    results["feedback"].append("❌ Chữ ký RSA không hợp lệ.")
            else:
                 results["feedback"].append("❌ Thiếu chữ ký RSA để kiểm tra.")
        except Exception as e:
            results["feedback"].append(f"❌ Lỗi xác thực RSA: {e}")

        # 3. Kiểm tra SHA (giữ nguyên vì nó tất định)
        if "sha256_hash" in player_answers:
            correct_hash = self.crypto_manager.sha256_hash(transaction_data)
            if player_answers["sha256_hash"] == correct_hash:
                results["sha_correct"] = True
                results["total_score"] += 30
                results["feedback"].append("✅ Hash SHA-256 chính xác!")
            else:
                results["feedback"].append("❌ Hash SHA-256 không chính xác")
        else:
            results["feedback"].append("❌ Thiếu SHA-256 hash để kiểm tra.")
        
        # --- KẾT THÚC SỬA LOGIC ---

        # Cập nhật điểm
        session.score += results["total_score"]
        session.transactions_processed += 1
        
        # Kiểm tra lên level
        if session.transactions_processed >= self.level_configs[session.level]["transaction_count"]:
            if session.level < 3:
                session.level += 1
                results["feedback"].append(f"🎉 Chúc mừng! Bạn đã lên Level {session.level}!")
        
        results["session_info"] = asdict(session)
        return results

# Khởi tạo game engine
game_engine = GameEngine()

# API Endpoints
@app.route('/api/start_game', methods=['POST'])
def start_game():
    """Bắt đầu game mới"""
    data = request.get_json() or {}
    player_name = data.get('player_name', 'Anonymous')
    
    session_id = game_engine.create_session(player_name)
    session = game_engine.get_session(session_id)
    
    if not session:
        return jsonify({"error": "Phiên không hợp lệ"}), 400

    return jsonify({
        "session_id": session_id,
        "session_info": asdict(session),
        "message": f"Chào mừng {player_name} đến với Hệ thống Bảo mật Ngân hàng!"
    })

@app.route('/api/get_transactions/<session_id>', methods=['GET'])
def get_transactions(session_id):
    """Lấy danh sách giao dịch cho level hiện tại"""
    session = game_engine.get_session(session_id)
    if not session:
        return jsonify({"error": "Phiên không hợp lệ"}), 400
    
    transactions = game_engine.get_transactions_for_level(session.level)
    return jsonify({
        "transactions": [asdict(txn) for txn in transactions],
        "level": session.level,
        "level_config": game_engine.level_configs[session.level]
    })

@app.route('/api/process_transaction', methods=['POST'])
def process_transaction():
    """Xử lý một giao dịch và trả về kết quả mã hóa"""
    data = request.get_json() or {}
    transaction_id = data.get('transaction_id')
    
    # Tìm giao dịch
    transaction = None
    for txn in game_engine.transaction_pool:
        if txn.id == transaction_id:
            transaction = txn
            break

    if not transaction:
        return jsonify({"error": "Giao dịch không tồn tại"}), 400

    result = game_engine.process_transaction_security(transaction)
    return jsonify(result)

@app.route('/api/verify_security', methods=['POST'])
def verify_security():
    """Kiểm tra kết quả bảo mật của người chơi"""
    data = request.get_json() or {}
    session_id = data.get('session_id')
    transaction_id = data.get('transaction_id')
    player_answers = data.get('answers', {})
    
    if not session_id or not transaction_id:
        return jsonify({"error": "Thiếu session_id hoặc transaction_id"}), 400

    result = game_engine.verify_security_steps(session_id, transaction_id, player_answers)
    return jsonify(result)

@app.route('/api/session_info/<session_id>', methods=['GET'])
def get_session_info(session_id):
    """Lấy thông tin phiên chơi"""
    session = game_engine.get_session(session_id)
    if not session:
        return jsonify({"error": "Phiên không hợp lệ"}), 400
    
    return jsonify(asdict(session))

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    """Bảng xếp hạng"""
    sessions = list(game_engine.sessions.values())
    sessions.sort(key=lambda x: x.score, reverse=True)
    
    leaderboard = []
    for i, session in enumerate(sessions[:10]):
        leaderboard.append({
            "rank": i + 1,
            "player_name": session.player_name,
            "score": session.score,
            "level": session.level,
            "transactions_processed": session.transactions_processed
        })
    return jsonify(leaderboard)

@app.route('/api/crypto_help', methods=['GET'])
def crypto_help():
    """Hướng dẫn về thuật toán mã hóa"""
    help_content = {
        "aes": {
            "name": "Advanced Encryption Standard (AES)",
            "description": "Thuật toán mã hóa đối xứng bảo vệ dữ liệu giao dịch",
            "key_size": "256 bit",
            "mode": "GCM (Galois/Counter Mode)"
        },
        "rsa": {
            "name": "Rivest-Shamir-Adleman (RSA)",
            "description": "Thuật toán mã hóa bất đối xứng để xác thực và chữ ký số",
            "key_size": "2048 bit",
            "purpose": "Đảm bảo tính xác thực và không thể chối bỏ"
        },
        "sha256": {
            "name": "Secure Hash Algorithm 256",
            "description": "Hàm băm mật mã đảm bảo tính toàn vẹn dữ liệu",
            "output_size": "256 bit (64 ký tự hex)",
            "purpose": "Phát hiện thay đổi dữ liệu"
        }
    }
    return jsonify(help_content)

if __name__ == '__main__':
    print("🏦 Banking Security Game Server")
    print("🔒 Hệ thống mô phỏng bảo mật ngân hàng")
    print("🚀 Server đang khởi động...")
    print("📡 API endpoint: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)