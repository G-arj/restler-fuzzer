# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

""" Implements logic for the user-directed invalid value checker. """
from __future__ import print_function

from checkers.checker_base import *
import time
import uuid
import json
import sys

from engine.bug_bucketing import BugBuckets
import engine.dependencies as dependencies
import engine.core.sequences as sequences
import engine.core.requests as requests
import engine.primitives as primitives

from engine.errors import TimeOutException

from utils.logger import raw_network_logging as RAW_LOGGING

class InvalidValueChecker(CheckerBase):
    """ Checker for fuzzing API parameters with invalid values. """
    # Dictionary used for determining whether or not a request has already
    # been sent for the current generation.
    # { generation : set(request.hex_definitions) }
    generation_executed_requests = dict()

    def __init__(self, req_collection, fuzzing_requests):
        CheckerBase.__init__(self, req_collection, fuzzing_requests)

        self._invalid_mutations_file_path = Settings().get_checker_arg(self._friendly_name, 'custom_dictionary')
        if self._invalid_mutations_file_path is None:
            print("You must provide a custom dictionary to use the invalid value checker")
            sys.exit(-1)

        try:
            self._custom_invalid_mutations = json.load(open(self._invalid_mutations_file_path, encoding='utf-8'))
        except Exception as error:
            print(f"Cannot import invalid mutations dictionary for checker: {error!s}")
            sys.exit(-1)

        self._max_invalid_combinations = Settings().get_checker_arg(self._friendly_name, 'max_combinations')
        if self._max_invalid_combinations is None:
            self._max_invalid_combinations = 100

    def apply(self, rendered_sequence, lock):
        """ Fuzzes each value in the parameters of this request as specified by
        the custom dictionary and settings for this checker.

        @param rendered_sequence: Object containing the rendered sequence information
        @type  rendered_sequence: RenderedSequence
        @param lock: Lock object used to sync more than one fuzzing job
        @type  lock: thread.Lock

        @return: None
        @rtype : None

        """
        # If this is not a valid sequence, do not attempt to fuzz the parameters.
        if not rendered_sequence.valid:
            return

        self._sequence = rendered_sequence.sequence
        last_request = self._sequence.last_request

        generation = self._sequence.length

        # Note: this hash must be the hex definition, so each of the different schema variations of the request
        # are fuzzed separately (since they may contain different parameters).
        request_hash = last_request.hex_definition
        if InvalidValueChecker.generation_executed_requests.get(generation) is None:
            # This is the first time this checker has seen this generation, create empty set of requests
            InvalidValueChecker.generation_executed_requests[generation] = set()
        elif request_hash in InvalidValueChecker.generation_executed_requests[generation]:
            # This request type has already been tested for this generation
            return
        # Add the last request to the generation_executed_requests dictionary for this generation
        InvalidValueChecker.generation_executed_requests[generation].add(request_hash)

        invalid_candidate_values_pool =  primitives.CandidateValuesPool()
        per_endpoint_invalid_custom_mutations = {} # TODO: support per-endpoint dict in this checker's settings
        invalid_candidate_values_pool.set_candidate_values(self._custom_invalid_mutations,
                                                           per_endpoint_invalid_custom_mutations)

        new_seq = None
        checked_seq = None
        req_async_wait = Settings().get_max_async_resource_creation_time(last_request.request_id)

        # Get a list of all the fuzzable parameters in this request.
        # The following list will contain a boolean value indicating whether the
        # corresponding request block is a parameter value that can be fuzzed.
        def is_fuzzable_parameter_value(request_block):
            primitive_type = request_block[0]
            return "_fuzzable_" in primitive_type or "_custom_" in primitive_type
        fuzzable_parameter_value_blocks=list(map(lambda x : is_fuzzable_parameter_value(x) , last_request.definition))

        # Render the current request combination, but get the list of primitive
        # values before they are concatenated.
        rendered_values, parser, tracked_parameters = \
            next(last_request.render_iter(self._req_collection.candidate_values_pool,
                                           skip=last_request._current_combination_id - 1,
                                           preprocessing=False,
                                           value_list=True))

        # For each fuzzable primitive, plug in all the values from the invalid dictionary.
        fuzzed_combinations = 0
        for idx, is_fuzzable in enumerate(fuzzable_parameter_value_blocks):
            if not is_fuzzable:
                continue

            # Save the original request block.
            request_block = last_request.definition[idx]
            primitive_type = request_block[0]

            # If this primitive type does not appear in the invalid dictionary,
            # there is nothing todo for this request block
            if primitive_type not in self._custom_invalid_mutations:
                continue
            # Execute the same check for custom payloads
            if "_custom_" in primitive_type:
                custom_payloads = self._custom_invalid_mutations[primitive_type]
                payload_name = request_block[1]
                if payload_name not in custom_payloads:
                    continue


            # Create a request with this block being the only part of its definition, and get the
            # fuzzable values.
            temp_req = requests.Request([request_block])

            invalid_candidate_values_pool._add_examples = False  # TODO
            fuzzable_values, _, _ = temp_req.init_fuzzable_values(temp_req.definition, invalid_candidate_values_pool)

            # The fuzzable values should always be a list of length 1, because only one request block is being fuzzed at a time
            if len(fuzzable_values) != 1:
                raise Exception(f"There should only be one item in fuzzable values, {len(fuzzable_values)} found.")

            # Now plug in this list into the rendered values, saving the original rendering
            orig_rendered_values=rendered_values[idx]
            try:
                for fuzzed_value in fuzzable_values[0]:

                    rendered_values[idx] = fuzzed_value
                    rendered_data = "".join(rendered_values)

                    # Execute the sequence prefix if it is not yet initialized
                    if new_seq is None:
                        new_seq = self._execute_start_of_sequence()

                        # Add the last request of the sequence to the new sequence
                        checked_seq = new_seq + sequences.Sequence(last_request)

                        # Create a placeholder sent data so it can be replaced below when bugs are detected for replay
                        checked_seq.append_data_to_sent_list(rendered_data, parser, HttpResponse(), max_async_wait_time=req_async_wait)

                    # Resolve dependencies
                    if not Settings().ignore_dependencies:
                        # TODO: perf.  Dependencies should be resolved once outside the
                        # loop.
                        rendered_data = checked_seq.resolve_dependencies(rendered_data)

                    # Check time budget
                    if Monitor().remaining_time_budget <= 0:
                        raise TimeOutException('Exceed Timeout')

                    if fuzzed_combinations > self._max_invalid_combinations:
                        break

                    fuzzed_combinations += 1

                    response = request_utilities.send_request_data(rendered_data)
                    responses_to_parse, resource_error, _ = async_request_utilities.try_async_poll(
                        rendered_data, response, req_async_wait)
                    parser_exception_occurred = False
                    # Response may not exist if there was an error sending the request or a timeout
                    if parser and responses_to_parse:
                        parser_exception_occurred = not request_utilities.call_response_parser(parser, None, request=last_request, responses=responses_to_parse)
                    status_code = response.status_code

                    if response and self._rule_violation(checked_seq, response, valid_response_is_violation=False):

                        checked_seq.replace_last_send_request_data(rendered_data, parser, response, max_async_wait_time=req_async_wait)
                        checked_seq.set_sent_requests_for_replay(new_seq.sent_request_data_list)
                        self._print_suspect_sequence(checked_seq, response)
                        BugBuckets.Instance().update_bug_buckets(checked_seq, response.status_code, origin=self.__class__.__name__)

            finally:
                rendered_values[idx] = orig_rendered_values

        self._checker_log.checker_print(f"Tested {fuzzed_combinations} combinations for request combination {last_request._current_combination_id}")
