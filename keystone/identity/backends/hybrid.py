# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# Copyright (c) 2016 Wind River Systems, Inc.
#

from __future__ import absolute_import

import copy
import ldap.filter
from oslo_log import log

import keystone.conf
from keystone import exception
from keystone.identity.backends import base

from keystone.identity.backends import ldap
from keystone.identity.backends import sql

from ldap import LDAPError
from ldappool import BackendError

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


class Identity(base.IdentityDriverBase):
    """Hybrid driver enabling a combined SQL and LDAP backend.

    The SQL backend stores the service and administrative configuration for
    users and groups.

    The LDAP backend stores the runtime configuration for users and groups.
    Service users and groups are considered read-only since they are created
    using the SQL backend directly, prior to having the hybrid backend driver.
    Domains are not currently supported by LDAP, but is still delegated to the
    LDAP backend for future support.

    """

    def __init__(self, conf=None):
        LOG.info("Initializing LDAP Hybrid Driver ...")
        super(Identity, self).__init__()
        if conf is None:
            self.conf = CONF
        else:
            self.conf = conf

        self.sql = sql.Identity(conf)
        self.ldap = ldap.Identity(conf)

    def is_domain_aware(self):
        # Note(knasim-wrs): the hybrid driver will now create users
        # in the SQL backend only, which is domain aware so we need to
        # support domain ids in the hybrid driver
        return self.sql.is_domain_aware()

    def generates_uuids(self):
        return self.ldap.generates_uuids()

    # Identity interface

    # Identity requests have changed in Newton due to the presence of
    # a local_user table (used to implement password policies).
    #  In Newton, if the user exists in the LDAP Identity backend,
    #  it will create an entry in the "user" table in Keystone.
    #  The local_user table will not have a reference to this entry.
    #  Therefore a call to authenticate will return a user reference
    #  which doesn't contain a local_user object, which causes failures.
    #  This is a limitation of the way hybrid driver aggregates
    #  both the SQL backend and the LDAP backend,
    #  since the local_user is used in the SQL backend to implement
    #  password policies and the same cannot be done in the
    #  LDAP backend since such password policies will need to
    #  be applied to the LDAP server itself.
    #  To overcome this error, "AttributeError"
    #  is also caught in this exception bloc
    def authenticate(self, user_id, password):
        try:
            return self.sql.authenticate(user_id, password)
        except (AssertionError, AttributeError):
            try:
                ref = self.ldap.authenticate(user_id, password)
                return ref
            except exception.LDAPServerConnectionError:
                # could not establish a connection to LDAP Server
                # in order to authenticate this user
                return None

    def get_user(self, user_id):
        # return self.user.get_filtered(user_id)
        try:
            return self.sql.get_user(user_id)
        except exception.UserNotFound:
            return self.ldap.get_user(user_id)

    def list_users(self, hints):
        users = []

        # The hybrid driver queries both the SQL backend as well
        # as the LDAP backend, make a copy of the hints since the
        # SQL driver will purge the hints filter list on match.
        ldap_hints = copy.deepcopy(hints)

        try:
            users += self.sql.list_users(hints)
            users += self.ldap.list_users(ldap_hints)
        except (LDAPError, BackendError,
                exception.LDAPServerConnectionError) as e:
            LOG.error(("Failed to query LDAP users: %s"), str(e))
        return users

    def unset_default_project_id(self, project_id):
        LOG.debug("unset_default_project_id %s: %s", project_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.unset_default_project_id(project_id)

    def get_user_by_name(self, user_name, domain_id):
        try:
            return self.sql.get_user_by_name(user_name, domain_id)
        except exception.UserNotFound:
            return self.ldap.get_user_by_name(user_name, domain_id)

    # CRUD
    # Note(knasim-wrs): LDAP Identity backend no longer
    # supports WRITE operations for users and groups
    # (as of Ocata). These will only be done in the SQL backend
    def create_user(self, user_id, user):
        LOG.debug("create_user %s: %s", user_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.create_user(user_id, user)

    def update_user(self, user_id, user):
        LOG.debug("update_user %s: %s", user_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.update_user(user_id, user)

    def change_password(self, user_id, new_password):
        LOG.debug("change_password %s: %s", user_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.change_password(user_id, new_password)

    def delete_user(self, user_id):
        LOG.debug("delete_user %s: %s", user_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.delete_user(user_id)

    def create_group(self, group_id, group):
        LOG.debug("create_group %s: %s", group_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.create_group(group_id, group)

    def get_group(self, group_id):
        try:
            return self.sql.get_group(group_id)
        except exception.GroupNotFound:
            return self.ldap.get_group(group_id)

    def get_group_by_name(self, group_name, domain_id):
        try:
            return self.sql.get_group_by_name(group_name, domain_id)
        except exception.GroupNotFound:
            return self.ldap.get_group_by_name(group_name, domain_id)

    def update_group(self, group_id, group):
        LOG.debug("update_group %s: %s", group_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.update_group(group_id, group)

    def delete_group(self, group_id):
        LOG.debug("delete_group %s: %s", group_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.delete_group(group_id)

    def add_user_to_group(self, user_id, group_id):
        LOG.debug("add_user_to_group %s,%s: %s", user_id, group_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.add_user_to_group(user_id, group_id)

    def remove_user_from_group(self, user_id, group_id):
        LOG.debug("remove_user_from_group %s,%s: %s", user_id, group_id,
                  ldap.READ_ONLY_LDAP_ERROR_MESSAGE)
        return self.sql.remove_user_from_group(user_id, group_id)

    def list_groups_for_user(self, user_id, hints):
        # The hybrid driver queries both the SQL backend as well
        # as the LDAP backend, make a copy of the hints since the
        # SQL driver will purge the hints filter list on match.
        ldap_hints = copy.deepcopy(hints)

        try:
            return self.sql.list_groups_for_user(user_id, hints)
        except exception.UserNotFound:
            return self.ldap.list_groups_for_user(user_id, ldap_hints)

    def list_groups(self, hints):
        groups = []

        # The hybrid driver queries both the SQL backend as well
        # as the LDAP backend, make a copy of the hints since the
        # SQL driver will purge the hints filter list on match.
        ldap_hints = copy.deepcopy(hints)

        try:
            groups += self.sql.list_groups(hints)
            groups += self.ldap.list_groups(ldap_hints)
        except (LDAPError, BackendError,
                exception.LDAPServerConnectionError) as e:
            LOG.error(("Failed to query LDAP groups: %s"), str(e))
        return groups

    def list_users_in_group(self, group_id, hints):
        # The hybrid driver queries both the SQL backend as well
        # as the LDAP backend, make a copy of the hints since the
        # SQL driver will purge the hints filter list on match.
        ldap_hints = copy.deepcopy(hints)

        try:
            return self.sql.list_users_in_group(group_id, hints)
        except exception.GroupNotFound:
            return self.ldap.list_users_in_group(group_id, ldap_hints)

    def check_user_in_group(self, user_id, group_id):
        try:
            return self.sql.check_user_in_group(user_id, group_id)
        except (exception.UserNotFound, exception.GroupNotFound):
            return self.ldap.check_user_in_group(user_id, group_id)
