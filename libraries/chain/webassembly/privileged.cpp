#include <eosio/chain/webassembly/interface.hpp>
#include <eosio/chain/global_property_object.hpp>
#include <eosio/chain/protocol_state_object.hpp>
#include <eosio/chain/transaction_context.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/apply_context.hpp>

#include <vector>
#include <set>

namespace eosio { namespace chain { namespace webassembly {

   int interface::is_feature_active( int64_t feature_name ) const { return false; }

   void interface::activate_feature( int64_t feature_name ) const {
      EOS_ASSERT( false, unsupported_feature, "Unsupported Hardfork Detected" );
   }

   void interface::preactivate_feature( legacy_ptr<const digest_type> feature_digest ) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "preactivate_feature not allowed in a readonly transaction");
      context.control.preactivate_feature( *feature_digest, context.trx_context.is_transient() );
   }

   void interface::set_resource_limits( account_name account, int64_t ram_bytes, int64_t net_weight, int64_t cpu_weight ) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_resource_limits not allowed in a readonly transaction");
      EOS_ASSERT(ram_bytes >= -1, wasm_execution_error, "invalid value for ram resource limit expected [-1,INT64_MAX]");
      EOS_ASSERT(net_weight >= -1, wasm_execution_error, "invalid value for net resource weight expected [-1,INT64_MAX]");
      EOS_ASSERT(cpu_weight >= -1, wasm_execution_error, "invalid value for cpu resource weight expected [-1,INT64_MAX]");
      if( context.control.get_mutable_resource_limits_manager().set_account_limits(account, ram_bytes, net_weight, cpu_weight, context.trx_context.is_transient()) ) {
         context.trx_context.validate_ram_usage.insert( account );
      }
   }

   void interface::get_resource_limits( account_name account, legacy_ptr<int64_t> ram_bytes, legacy_ptr<int64_t> net_weight, legacy_ptr<int64_t> cpu_weight ) const {
      context.control.get_resource_limits_manager().get_account_limits( account, *ram_bytes, *net_weight, *cpu_weight);
      (void)legacy_ptr<int64_t>(std::move(ram_bytes));
      (void)legacy_ptr<int64_t>(std::move(net_weight));
      (void)legacy_ptr<int64_t>(std::move(cpu_weight));
   }

   int64_t set_proposed_producers_common( apply_context& context, vector<producer_authority> && producers, bool validate_keys ) {
      EOS_ASSERT(producers.size() <= config::max_producers, wasm_execution_error, "Producer schedule exceeds the maximum producer count for this chain");
      EOS_ASSERT( producers.size() > 0
                  || !context.control.is_builtin_activated( builtin_protocol_feature_t::disallow_empty_producer_schedule ),
                  wasm_execution_error,
                  "Producer schedule cannot be empty"
      );

      const size_t num_supported_key_types = context.db.get<protocol_state_object>().num_supported_key_types;

      // check that producers are unique
      std::set<account_name> unique_producers;
      for (const auto& p: producers) {
         EOS_ASSERT( context.is_account(p.producer_name), wasm_execution_error, "producer schedule includes a nonexisting account" );
         std::visit([&p, num_supported_key_types, validate_keys](const auto& a) {
            uint32_t sum_weights = 0;
            std::set<public_key_type> unique_keys;
            for (const auto& kw: a.keys ) {
               EOS_ASSERT( kw.key.which() < num_supported_key_types, unactivated_key_type,
                           "Unactivated key type used in proposed producer schedule");

               if( validate_keys ) {
                  EOS_ASSERT( kw.key.valid(), wasm_execution_error, "producer schedule includes an invalid key" );
               }

               if (std::numeric_limits<uint32_t>::max() - sum_weights <= kw.weight) {
                  sum_weights = std::numeric_limits<uint32_t>::max();
               } else {
                  sum_weights += kw.weight;
               }

               unique_keys.insert(kw.key);
            }

            EOS_ASSERT( a.keys.size() == unique_keys.size(), wasm_execution_error, "producer schedule includes a duplicated key for ${account}", ("account", p.producer_name));
            EOS_ASSERT( a.threshold > 0, wasm_execution_error, "producer schedule includes an authority with a threshold of 0 for ${account}", ("account", p.producer_name));
            EOS_ASSERT( sum_weights >= a.threshold, wasm_execution_error, "producer schedule includes an unsatisfiable authority for ${account}", ("account", p.producer_name));
         }, p.authority);

         unique_producers.insert(p.producer_name);
      }
      EOS_ASSERT( producers.size() == unique_producers.size(), wasm_execution_error, "duplicate producer name in producer schedule" );

      return context.control.set_proposed_producers( std::move(producers) );
   }

   uint32_t interface::get_wasm_parameters_packed( span<char> packed_parameters, uint32_t max_version ) const {
      auto& gpo = context.control.get_global_properties();
      auto& params = gpo.wasm_configuration;
      uint32_t version = std::min( max_version, uint32_t(0) );

      auto s = fc::raw::pack_size( version ) + fc::raw::pack_size( params );
      if ( packed_parameters.size() == 0 )
         return s;

      if ( s <= packed_parameters.size() ) {
         datastream<char*> ds( packed_parameters.data(), s );
         fc::raw::pack(ds, version);
         fc::raw::pack(ds, params);
      }
      return s;
   }
   void interface::set_wasm_parameters_packed( span<const char> packed_parameters ) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_wasm_parameters_packed not allowed in a readonly transaction");
      datastream<const char*> ds( packed_parameters.data(), packed_parameters.size() );
      uint32_t version;
      chain::wasm_config cfg;
      fc::raw::unpack(ds, version);
      EOS_ASSERT(version == 0, wasm_config_unknown_version, "set_wasm_parameters_packed: Unknown version: ${version}", ("version", version));
      fc::raw::unpack(ds, cfg);
      cfg.validate();
      context.db.modify( context.control.get_global_properties(),
         [&]( auto& gprops ) {
            gprops.wasm_configuration = cfg;
         }
      );
   }
   int64_t interface::set_proposed_producers( legacy_span<const char> packed_producer_schedule) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_proposed_producers not allowed in a readonly transaction");
      datastream<const char*> ds( packed_producer_schedule.data(), packed_producer_schedule.size() );
      std::vector<producer_authority> producers;
      std::vector<legacy::producer_key> old_version;
      fc::raw::unpack(ds, old_version);

      /*
       * Up-convert the producers
       */
      for ( const auto& p : old_version ) {
         producers.emplace_back( producer_authority{ p.producer_name, block_signing_authority_v0{ 1, {{p.block_signing_key, 1}} } } );
      }

      return set_proposed_producers_common( context, std::move(producers), true );
   }

   int64_t interface::set_proposed_producers_ex( uint64_t packed_producer_format, legacy_span<const char> packed_producer_schedule) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_proposed_producers_ex not allowed in a readonly transaction");
      if (packed_producer_format == 0) {
         return set_proposed_producers(std::move(packed_producer_schedule));
      } else if (packed_producer_format == 1) {
         datastream<const char*> ds( packed_producer_schedule.data(), packed_producer_schedule.size() );
         vector<producer_authority> producers;

         fc::raw::unpack(ds, producers);
         return set_proposed_producers_common( context, std::move(producers), false);
      } else {
         EOS_THROW(wasm_execution_error, "Producer schedule is in an unknown format!");
      }
   }

   int64_t interface::set_proposed_finalizers(legacy_span<const char> packed_finalizer_schedule) {

      // A finalizer_authority is the same as a producer_authority (producer name, sig threshold & array of weighted keys) but with an
      //       additional integer weight associated with the named finalizer itself, so (finalizer name, finalizer weight, sig threshold
      //       & array of weighted keys).

      // A finalizer schedule is a set of finalizer authorities, a version, and a global integer finalization threshold (satisfied/crossed
      //       by doing a sum over the weights of the finalizers that are e.g. finalizing a block).

      // TODO: Verify that the finalizer schedule threshold can ever be satisfied in by the distribution of weights associated with each named
      //       finalizer. For this to be true, the sum of all finalizer weights has to be greater or equal than the schedule's threshold.

      // TODO: Verify that the integer threshold cannot ever be satisfied in an invalid manner.
      //       For this to be true, the finalizers are sorted in descending weight order and the sum is computed. If the sum satisfies the
      //       global threshold before more than half of the finalizer set is scanned, then the proposed finalizer schedule is invalid.

      // TODO: Verify that the finalizer keys are of the new BLS agg sig type that is going to be registered upon feature activation.

      /*
      TODO: delete this / move to docs

      The producer schedule is not removed from the code, but it can be either disabled or adapted/modified after feature activation and
      set_proposed_finalizers takes effect.

      What we probably should do is keep the producer schedule as:
      - configuring the set of supernodes that are chosen (e.g. by system-contract governance) to be in the master whitelist for various roles
        for which there isn't a dedicated schedule configured (like the finalizer schedule that defines the "congress" that votes for block finalization)
      - the hotstuff protocol proposer set and schedule is sourced directly (1:1) from the producer set and schedule
      - the hotstuff protocol leader set is sourced directly (1:1) from the producer set -- exactly how the hotstuff protocol leadership role is
        fulfilled is mostly an implementation detail, with (perhaps) some BP config.ini variables to help customize it.

      The hotstuff protocol finalizer set does not need to overlap with the producer (proposer/leader) set, but what makes most sense
      is for every producer (whitelisted supernode) to be able to act as a hotstuff proposer, leader, and finalizer (voter), thus all these
      sets should probably be the same by default.

      Calling set_proposed_finalizers after feature activation is what really starts IF. When the feature is activated, what happens is that
      the set_proposed_finalizers intrinsic/hostfunction is whitelisted for execution (and the BLS key type is enabled). Then, only after
      set_proposed_finalizers is called, and its proposed hotstuff finalization protocol configuration is processed and accepted into the
      chain (the first version of the finalizer_schedule), is that the *next* blocks start being able to be finalized through hotstuff consensus.

      Data structures:

      finalizer_schedule {
         uint       version;
         uint64     fthreshold;  // for finalization: sum of finalizer weights signing for finality
         vector<finalizer_authority>  finalizers;
      }

      finalizer_authority {
         name                            finalizer_name;
         uint64                          fweight; (among all finalizers)
         block_finalization_authority    authority; // NEW: just one key per finalizer
      }
      */

      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_proposed_finalizers not allowed in a readonly transaction");
      datastream<const char*> ds( packed_finalizer_schedule.data(), packed_finalizer_schedule.size() );
      finalizer_schedule schedule;
      fc::raw::unpack(ds, schedule);
      vector<finalizer_authority> & finalizers = schedule.finalizers;

      EOS_ASSERT( finalizers.size() <= config::max_finalizers, wasm_execution_error, "Finalizer schedule exceeds the maximum finalizer count for this chain" );
      EOS_ASSERT( finalizers.size() > 0, wasm_execution_error, "Finalizer schedule cannot be empty" );

      const size_t num_supported_key_types = context.db.get<protocol_state_object>().num_supported_key_types;

      // check that finalizers are unique and that the keys are valid BLS keys
      std::set<account_name> unique_finalizers;
      for (const auto& f: finalizers) {
         EOS_ASSERT( context.is_account(f.finalizer_name), wasm_execution_error, "Finalizer schedule includes a nonexisting account" );
         EOS_ASSERT( f.public_key.which() < num_supported_key_types, unactivated_key_type, "Unactivated key type used in proposed finalizer schedule" );
         EOS_ASSERT( f.public_key.valid(), wasm_execution_error, "Finalizer schedule includes an invalid key" );

         // -------------------------------------------
         // FIXME/TODO: check for BLS/aggsig key type here
         // -------------------------------------------

         unique_finalizers.insert(f.finalizer_name);
      }
      EOS_ASSERT( finalizers.size() == unique_finalizers.size(), wasm_execution_error, "Duplicate finalizer name in finalizer schedule" );

      return context.control.set_proposed_finalizers( schedule.fthreshold, std::move(finalizers) );
   }

   uint32_t interface::get_blockchain_parameters_packed( legacy_span<char> packed_blockchain_parameters ) const {
      auto& gpo = context.control.get_global_properties();

      auto s = fc::raw::pack_size( gpo.configuration.v0() );
      if( packed_blockchain_parameters.size() == 0 ) return s;

      if ( s <= packed_blockchain_parameters.size() ) {
         datastream<char*> ds( packed_blockchain_parameters.data(), s );
         fc::raw::pack(ds, gpo.configuration.v0());
         return s;
      }
      return 0;
   }

   void interface::set_blockchain_parameters_packed( legacy_span<const char> packed_blockchain_parameters ) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_blockchain_parameters_packed not allowed in a readonly transaction");
      datastream<const char*> ds( packed_blockchain_parameters.data(), packed_blockchain_parameters.size() );
      chain::chain_config_v0 cfg;
      fc::raw::unpack(ds, cfg);
      cfg.validate();
      context.db.modify( context.control.get_global_properties(),
         [&]( auto& gprops ) {
              gprops.configuration = cfg;
      });
   }

   uint32_t interface::get_parameters_packed( span<const char> packed_parameter_ids, span<char> packed_parameters) const{
      datastream<const char*> ds_ids( packed_parameter_ids.data(), packed_parameter_ids.size() );

      chain::chain_config cfg = context.control.get_global_properties().configuration;
      std::vector<fc::unsigned_int> ids;
      fc::raw::unpack(ds_ids, ids);
      const config_range config_range(cfg, std::move(ids), {context.control});

      auto size = fc::raw::pack_size( config_range );
      if( packed_parameters.size() == 0 ) return size;

      EOS_ASSERT(size <= packed_parameters.size(),
                 chain::config_parse_error,
                 "get_parameters_packed: buffer size is smaller than ${size}", ("size", size));

      datastream<char*> ds( packed_parameters.data(), size );
      fc::raw::pack( ds, config_range );
      return size;
   }

   void interface::set_parameters_packed( span<const char> packed_parameters ){
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_parameters_packed not allowed in a readonly transaction");
      datastream<const char*> ds( packed_parameters.data(), packed_parameters.size() );

      chain::chain_config cfg = context.control.get_global_properties().configuration;
      config_range config_range(cfg, {context.control});

      fc::raw::unpack(ds, config_range);

      config_range.config.validate();
      context.db.modify( context.control.get_global_properties(),
         [&]( auto& gprops ) {
              gprops.configuration = config_range.config;
      });
   }

   bool interface::is_privileged( account_name n ) const {
      return context.db.get<account_metadata_object, by_name>( n ).is_privileged();
   }

   void interface::set_privileged( account_name n, bool is_priv ) {
      EOS_ASSERT(!context.trx_context.is_read_only(), wasm_execution_error, "set_privileged not allowed in a readonly transaction");
      const auto& a = context.db.get<account_metadata_object, by_name>( n );
      context.db.modify( a, [&]( auto& ma ){
         ma.set_privileged( is_priv );
      });
   }
}}} // ns eosio::chain::webassembly
