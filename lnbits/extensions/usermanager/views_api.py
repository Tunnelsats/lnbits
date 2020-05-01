from flask import g, jsonify, request

from lnbits.core.crud import get_user
from lnbits.decorators import api_check_wallet_key, api_validate_post_request
from lnbits.helpers import Status

from lnbits.extensions.usermanager import usermanager_ext
from .crud import create_usermanager_user, get_usermanager_user, get_usermanager_users, get_usermanager_wallet_transactions, get_usermanager_wallet_balances, delete_usermanager_user, create_usermanager_wallet, get_usermanager_wallet, get_usermanager_wallets, delete_usermanager_wallet
from lnbits.core.services import create_invoice
from base64 import urlsafe_b64encode
from uuid import uuid4
from lnbits.db import open_ext_db



###Users

@usermanager_ext.route("/api/v1/users", methods=["GET"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_users():
    user_id = g.wallet.user
    return jsonify([user._asdict() for user in get_usermanager_users(user_id)]), Status.OK


@usermanager_ext.route("/api/v1/users", methods=["POST"])
@api_check_wallet_key(key_type="invoice")
@api_validate_post_request(schema={
    "admin_id": {"type": "string", "empty": False, "required": True},
    "user_name": {"type": "string", "empty": False, "required": True},
    "wallet_name": {"type": "string", "empty": False, "required": True}
})
def api_usermanager_users_create():
    user = create_usermanager_user(g.data["user_name"], g.data["wallet_name"], g.data["admin_id"])
    return jsonify(user._asdict()), Status.CREATED


@usermanager_ext.route("/api/v1/users/<user_id>", methods=["DELETE"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_users_delete(user_id):
    print("cunt")
    user = get_usermanager_user(user_id)
    if not user:
        return jsonify({"message": "User does not exist."}), Status.NOT_FOUND
    delete_usermanager_user(user_id)
    return "", Status.NO_CONTENT


###Wallets

@usermanager_ext.route("/api/v1/wallets", methods=["GET"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_wallets():
    user_id = g.wallet.user
    return jsonify([wallet._asdict() for wallet in get_usermanager_wallets(user_id)]), Status.OK


@usermanager_ext.route("/api/v1/wallets", methods=["POST"])
@api_check_wallet_key(key_type="invoice")
@api_validate_post_request(schema={
    "user_id": {"type": "string", "empty": False, "required": True},
    "wallet_name": {"type": "string", "empty": False, "required": True},
    "admin_id": {"type": "string", "empty": False, "required": True}
    
})
def api_usermanager_wallets_create():
    user = create_usermanager_wallet(g.data["user_id"], g.data["wallet_name"], g.data["admin_id"])
    return jsonify(user._asdict()), Status.CREATED


@usermanager_ext.route("/api/v1/wallets<wallet_id>", methods=["GET"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_wallet_transactions(wallet_id):

    return jsonify(get_usermanager_wallet_transactions(wallet_id)), Status.OK

@usermanager_ext.route("/api/v1/wallets/<user_id>", methods=["GET"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_wallet_balances(user_id):
    return jsonify(get_usermanager_wallet_balances(user_id)), Status.OK


@usermanager_ext.route("/api/v1/wallets/<wallet_id>", methods=["DELETE"])
@api_check_wallet_key(key_type="invoice")
def api_usermanager_wallets_delete(wallet_id):
    wallet = get_usermanager_wallet(wallet_id)
    print(wallet.id)
    if not wallet:
        return jsonify({"message": "Wallet does not exist."}), Status.NOT_FOUND

    delete_usermanager_wallet(wallet_id, wallet.user)

    return "", Status.NO_CONTENT

