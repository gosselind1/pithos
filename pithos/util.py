# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; -*-
# Copyright (C) 2010-2012 Kevin Mehall <km@kevinmehall.net>
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.


import logging
import os
from urllib.parse import splittype, splituser, splitpasswd

import gi
from gi.repository import (
    GLib,
    Gtk
)
import keyring.errors
import keyring


class _SecretService:

    _SERVICE_NAME = 'io.github.Pithos.Account'

    def __init__(self):
        pass  # as collections have been passed off to secrets, this shouldn't need to track anything

    @staticmethod
    def unlock_keyring(callback):
        """
        Name is somewhat misleading now.
        Serves as a keyring initializer rather than a gtk secret1 unlocker now.
        """

        try:
            logging.debug('Keyring backend: {}'.format(keyring.get_keyring().name))
        except keyring.errors.InitError as e:
            logging.error('Failed to init keyring, Error: {}'.format(e))

        callback(None)

    def get_account_password(self, email, callback):
        password = ''

        try:
            password = keyring.get_password(self._SERVICE_NAME, email) or ''
        except keyring.errors.KeyringError as e:
            logging.error('Failed to lookup password, Error: {}'.format(e))

        finally:
            callback(password)

    def set_account_password(self, old_email, new_email, password, callback):
        """
        Attempts to set an account password.
        Deletes the previously stored password if the new email does not match the previously stored one.
        """
        success = True

        if old_email and old_email != new_email:
            try:
                keyring.delete_password(self._SERVICE_NAME, old_email)
                logging.debug('Cleared password for: {}'.format(old_email))

            except keyring.errors.PasswordDeleteError as e:
                logging.debug('Failed to clear password for: {}, Clear Error: {}'.format(old_email, e))

            except keyring.errors.KeyringError as e:
                logging.error('Failed to clear password for: {}, Critical Error: {}'.format(old_email, e))
                success = False

        try:
            keyring.set_password(self._SERVICE_NAME, new_email, password)

        except keyring.errors.KeyringError as e:
            logging.error('Failed to store password, Error: {}'.format(e))
            success = False

        if callback:
            callback(success)


SecretService = _SecretService()


def parse_proxy(proxy):
    """ _parse_proxy from urllib """
    scheme, r_scheme = splittype(proxy)
    if not r_scheme.startswith("/"):
        # authority
        scheme = None
        authority = proxy
    else:
        # URL
        if not r_scheme.startswith("//"):
            raise ValueError("proxy URL with no authority: %r" % proxy)
        # We have an authority, so for RFC 3986-compliant URLs (by ss 3.
        # and 3.3.), path is empty or starts with '/'
        end = r_scheme.find("/", 2)
        if end == -1:
            end = None
        authority = r_scheme[2:end]
    userinfo, hostport = splituser(authority)
    if userinfo is not None:
        user, password = splitpasswd(userinfo)
    else:
        user = password = None
    return scheme, user, password, hostport


def open_browser(url, parent=None, timestamp=0):
    logging.info("Opening URL {}".format(url))
    if not timestamp:
        timestamp = Gtk.get_current_event_time()
    try:
        if hasattr(Gtk, 'show_uri_on_window'):
            Gtk.show_uri_on_window(parent, url, timestamp)
        else: # Gtk <= 3.20
            screen = None
            if parent:
                screen = parent.get_screen()
            Gtk.show_uri(screen, url, timestamp)
    except GLib.Error as e:
        logging.warning('Failed to open URL: {}'.format(e.message))

if hasattr(Gtk.Menu, 'popup_at_pointer'):
    popup_at_pointer = Gtk.Menu.popup_at_pointer
else:
    popup_at_pointer = lambda menu, event: menu.popup(None, None, None, None, event.button, event.time)

_is_flatpak = None
def is_flatpak() -> bool:
    global _is_flatpak

    if _is_flatpak is None:
        _is_flatpak = os.path.exists('/.flatpak-info')

    return _is_flatpak
