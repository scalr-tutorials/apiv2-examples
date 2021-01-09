# coding:utf-8
import logging
import unittest

import nose.core
from requests import HTTPError


logger = logging.getLogger(__name__)


OS_TRUSTY = {
    # ID is needed to use this for Roles
    "id": "ubuntu-14-04",
    # Those are just here to use in asserts in the test code
    "family": "ubuntu",
    "version": "14.04",
}

OS_PRECISE = {
    "id": "ubuntu-12-04",
}

IMG_TRUSTY = {
    "name": "api-test-image-trusty",
    "cloudImageId": "ami-10b68a78",
    "cloudPlatform": "ec2",
    "cloudLocation": "us-east-1",
    "architecture": "x86_64",
    "os": OS_TRUSTY,
}

IMG_TRUSTY_HVM = dict(IMG_TRUSTY)
IMG_TRUSTY_HVM.update({
    "name": "api-test-image-trusty-hvm",
    "cloudImageId": "ami-de132bb6",
    "type": "lol",  # (???)
})

IMG_PRECISE = dict(IMG_TRUSTY)
IMG_PRECISE.update({
    "name": "api-test-image-precise",
    "cloudImageId": "ami-f6132b9e",
    "os": OS_PRECISE
})

ROLE = {
    "name": "api-test-role",
    "category": {"id": 1},  # Currently there is no API for Role Categories
    "os": OS_TRUSTY,
}

GLOBAL_VARIABLE = [
    {
        "name": "TEST",
        "value": "123",
        "hidden": True,
        "outputFormat": "TEST=%s",
        "validationPattern": "^\d+$",
    },
    {
        "name": "REQUIRED",
        "requiredIn": "farmrole",
    },
]



def list_os(client, **params):
    return client.list("/api/v1beta0/user/os/", params=params)


def list_images(client, env_id, **params):
    return client.list("/api/v1beta0/user/{0}/images/".format(env_id), params=params)


def create_image(client, env_id, img):
    logger.info("Creating Image: %s", img["name"])
    return client.create("/api/v1beta0/user/{0}/images/".format(env_id), json=img)


def delete_image(client, env_id, image):
    logger.info("Deleting Image: %s", image["name"])
    client.delete("/api/v1beta0/user/{0}/images/{1}/".format(env_id, image["id"]))


def list_roles(client, env_id, **params):
    return client.list("/api/v1beta0/user/{0}/roles/".format(env_id), params=params)


def create_role(client, env_id, role):
    logger.info("Creating Role: %s", role["name"])
    return client.create("/api/v1beta0/user/{0}/roles/".format(env_id), json=role)


def delete_role(client, env_id, role):
    logger.info("Deleting Role: %s", role["name"])
    client.delete("/api/v1beta0/user/{0}/roles/{1}/".format(env_id, role["id"]))


def list_role_images(client, env_id, role):
    return client.list("/api/v1beta0/user/{0}/roles/{1}/images/".format(env_id, role["id"]))


def associate_role_image(client, env_id, role, image):
    logger.info("Associating Image %s with Role %s", image["name"], role["name"])
    return client.create("/api/v1beta0/user/{0}/roles/{1}/images/".format(env_id, role["id"]), json={"image": image})


def dissociate_role_image(client, env_id, role, image):
    logger.info("Disassociating Image %s from Role %s", image["name"], role["name"])
    client.delete("/api/v1beta0/user/{0}/roles/{1}/images/{2}/".format(env_id, role["id"], image["id"]))


def replace_role_image(client, env_id, role, old_image, new_image):
    client.post("/api/v1beta0/user/{0}/roles/{1}/images/{2}/actions/replace/".format(env_id, role["id"], old_image["id"]),
                 json={"image": new_image})


def set_role_global_variable(client, env_id, role, gv):
    logger.info("Setting Global Variable on Role %s: %s=%s", role["name"], gv["name"], gv.get("value", ""))
    client.create("/api/v1beta0/user/{0}/roles/{1}/global-variables/".format(env_id, role["id"]), json=gv)


def list_global_variables(client, env_id, role):
    logger.info("Listing Global Variables on Role %s", role["name"])
    return client.list("/api/v1beta0/user/{0}/roles/{1}/global-variables/".format(env_id, role["id"]))


def delete_role_global_variable(client, env_id, role, gv):
    logger.info("Deleting Global Variable from Role %s: %s", role["name"], gv["name"])
    return client.delete("/api/v1beta0/user/{0}/roles/{1}/global-variables/{2}/".format(env_id, role["id"], gv["name"]))


class BaseApiTestCase(unittest.TestCase):
    def __init__(self, client, env_id):
        super(BaseApiTestCase, self).__init__()
        self.client = client
        self.env_id = env_id

    def _cleanup(self):
        role_names = [role["name"] for role in [ROLE]]
        image_names = [img["name"] for img in [IMG_TRUSTY, IMG_TRUSTY_HVM, IMG_PRECISE]]

        for role in list_roles(self.client, self.env_id, scope="environment"):
            if role["name"] in role_names:
                delete_role(self.client, self.env_id, role)

        for img in list_images(self.client, self.env_id, scope="environment"):
            if img["name"] in image_names:
                delete_image(self.client, self.env_id, img)


    def setUp(self):
        self._cleanup()
        #self.os = find_os(self.client)  # TODO - Test OS API

        # Create Image
        self.image = create_image(self.client, self.env_id, IMG_TRUSTY)

        # Create Role, and scheduling it for cleanup
        self.role = create_role(self.client, self.env_id, ROLE)

    def tearDown(self):
            self._cleanup()

    def runTest(self):
        raise NotImplementedError()


    # Assert methods

    def _role_has_image(self, role, image):
        for role_image in list_role_images(self.client, self.env_id, role):
            if role_image["image"]["id"] == image["id"]:
                return True
        return False

    def assertRoleHasImage(self, role, image):
        if not self._role_has_image(role, image):
            self.fail(self.failureException("Role %s (%s) has no Image %s (%s)" %
                                            (role["name"], role["id"], image["name"], image["id"])))

    def assertRoleDoesNotHaveImage(self, role, image):
        if self._role_has_image(role, image):
            self.fail(self.failureException("Role %s (%s) has Image %s (%s)" %
                                            (role["name"], role["id"], image["name"], image["id"])))


class SimpleApiTestCase(BaseApiTestCase):
    def runTest(self):
        pass


class GvsTestCase(BaseApiTestCase):
    def runTest(self):
        for gv in GLOBAL_VARIABLE:
            set_role_global_variable(self.client, self.env_id, self.role, gv)

        for gv in list_global_variables(self.client, self.env_id, self.role):
            # Check GV booleans are indeed booleans
            for attr in ["hidden", "locked"]:
                self.assertIsInstance(gv[attr], bool)

            # Check they can be deleted
            if gv["declaredIn"] == "role":
                delete_role_global_variable(self.client, self.env_id, self.role, gv)



class ReplaceImageTestCase(BaseApiTestCase):
    def runTest(self):
        trusty_hvm = create_image(self.client, self.env_id, IMG_TRUSTY_HVM)

        associate_role_image(self.client, self.env_id, self.role, self.image)
        replace_role_image(self.client, self.env_id, self.role, self.image, trusty_hvm)

        self.assertRoleHasImage(self.role, trusty_hvm)
        self.assertRoleDoesNotHaveImage(self.role, self.image)


class DissociateImageTestCase(BaseApiTestCase):
    def runTest(self):
        # Associate, disassociate
        associate_role_image(self.client, self.env_id, self.role, self.image)
        self.assertRoleHasImage(self.role, self.image)

        dissociate_role_image(self.client, self.env_id, self.role, self.image)
        self.assertRoleDoesNotHaveImage(self.role, self.image)

        # Check 404
        self.assertRaises(HTTPError, dissociate_role_image,
                          self.client, self.env_id, self.role, self.image)


class AssociateConflictingImageTestCase(BaseApiTestCase):
    def runTest(self):
        # Check conflict
        trusty_hvm = create_image(self.client, self.env_id, IMG_TRUSTY_HVM)

        associate_role_image(self.client, self.env_id, self.role, self.image)

        self.assertRaises(HTTPError, associate_role_image,
                          self.client, self.env_id, self.role, trusty_hvm)
        self.assertRoleHasImage(self.role, self.image)
        self.assertRoleDoesNotHaveImage(self.role, trusty_hvm)


class AssociateConflictingOsImageTestCase(BaseApiTestCase):
    def runTest(self):
        precise = create_image(self.client, self.env_id, IMG_PRECISE)
        self.assertRaises(HTTPError, associate_role_image,
                          self.client, self.env_id, self.role, precise)
        self.assertRoleDoesNotHaveImage(self.role, precise)


class DeleteAssociatedImageTestCase(BaseApiTestCase):
    def runTest(self):
        associate_role_image(self.client, self.env_id, self.role, self.image)
        self.assertRaises(HTTPError, delete_image, self.client, self.env_id, self.image)


class TestListOsTestCase(BaseApiTestCase):
    def runTest(self):
        kwargs = {k: OS_TRUSTY[k] for k in ["family", "version"]}
        match = list_os(self.client, **kwargs)
        self.assertEqual(1, len(match))

        for k, v in list(kwargs.items()):
            self.assertEqual(match[0][k], OS_TRUSTY[k])


def execute(client, env_id):
    suite = [cls(client, env_id) for cls in BaseApiTestCase.__subclasses__()]
    nose.core.TestProgram(suite=suite)
