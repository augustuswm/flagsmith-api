from collections import namedtuple
import json

from django.core.exceptions import ObjectDoesNotExist

import coreapi
from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.schemas import AutoSchema

from app.pagination import CustomPagination
from environments.identities.helpers import identify_integrations
from environments.identities.models import Identity
from environments.identities.serializers import IdentitySerializer
from environments.identities.traits.models import Trait
from environments.identities.traits.serializers import TraitSerializerBasic
from environments.models import Environment
from environments.permissions.permissions import NestedEnvironmentPermissions
from environments.sdk.serializers import (
    IdentifyWithTraitsSerializer,
    IdentitySerializerWithTraitsAndSegments,
)
from features.serializers import FeatureStateSerializerFull
from util.views import SDKAPIView

class SDKEvaluations(SDKAPIView):
    pagination_class = None

    def get(self, request):
        identifier = request.query_params.get("identifier")

        if identifier is None:
            return Response(
                {"detail": "Missing identifier"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            identity = (
                Identity.objects.select_related(
                    "environment", "environment__project")
                .prefetch_related("identity_traits", "environment__project__segments")
                .get(identifier=identifier, environment=request.environment)
            )
        except ObjectDoesNotExist:
            identity = Identity(identifier=identifier,
                                environment=request.environment)

        # Create temporary trait models
        temporary_traits = request.query_params.get("traits")

        try:
            if temporary_traits:
                decoded_traits = json.loads(temporary_traits)
                traits = list(map(lambda t: self._make_temporary_trait(
                    identity, t), decoded_traits))
            else:
                traits = None
        except json.JSONDecodeError:
            return Response(
                {"detail": "Unable to parse traits"}, status=status.HTTP_400_BAD_REQUEST
            )

        features = request.query_params.get("features")

        try:
            if features:
                features_list = json.loads(features)
            else:
                features_list = None
        except json.JSONDecodeError:
            return Response(
                {"detail": "Unable to parse features list"}, status=status.HTTP_400_BAD_REQUEST
            )

        return self._get_feature_states_for_user_response(identity, traits, features_list)

    def _get_feature_states_for_user_response(self, identity, trait_models=None, features=None):
        """
        Get all feature (or a subset of them) states for an identity

        :param identity: Identity model to return feature states for
        :param trait_models: optional list of trait_models to apply over top of any already persisted traits for the identity
        :return: Response containing lists of both serialized flags and traits
        """
        shadowed_keys = [] if trait_models is None else map(
            lambda t: t.trait_key, trait_models)

        traits = identity.identity_traits.all() if trait_models is None else list(
            identity.identity_traits.all().exclude(trait_key__in=shadowed_keys)) + trait_models

        if features is None:
            feature_states = identity.get_all_feature_states(traits)
        else:
            feature_states = identity.get_feature_states(features, traits)

        serialized_flags = FeatureStateSerializerFull(
            feature_states, many=True)

        serialized_traits = TraitSerializerBasic(
            traits, many=True
        )

        identify_integrations(identity, feature_states)

        response = {"flags": serialized_flags.data,
                    "traits": serialized_traits.data}

        return Response(data=response, status=status.HTTP_200_OK)


    def _make_temporary_trait(self, identity, trait_data):
        print(trait_data)
        return Trait(
            identity=identity,
            trait_key=trait_data.get('trait_key'),
            value_type=trait_data.get('value_type'),
            boolean_value=trait_data.get('boolean_value'),
            integer_value=trait_data.get('integer_value'),
            string_value=trait_data.get('string_value'),
            float_value=trait_data.get('float_value')
        )