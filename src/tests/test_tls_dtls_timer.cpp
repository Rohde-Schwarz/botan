/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)

   #include <botan/internal/tls_timer_dtls13.h>
   #include <algorithm>

namespace Botan_Tests {

namespace {

class Timer_Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> /*data*/) override {}

      void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> /*data*/) override {}

      void tls_alert(Botan::TLS::Alert /*alert*/) override {}

      uint64_t tls_current_monotonic_clock_ms() override { return m_now_ms; }

      void tls_register_deferred_operation(uint64_t monotonic_delay_ms, std::function<void()> op) override {
         const uint64_t deadline_ms = tls_current_monotonic_clock_ms() + monotonic_delay_ms;
         m_deferred_ops.emplace_back(Deferred_Operation{
            .deadline_ms = deadline_ms,
            .op = std::move(op),
         });
      }

      void advance(std::chrono::milliseconds delta) {
         m_now_ms += delta.count();

         // Collect the due operations before invoking them, because an invoked
         // operation may register new deferred operations (e.g. the retransmission
         // timer re-arms itself) and thereby invalidate iterators of m_deferred_ops.
         std::vector<std::function<void()>> due_ops;
         std::erase_if(m_deferred_ops, [this, &due_ops](Deferred_Operation& op) {
            if(op.deadline_ms <= m_now_ms) {
               due_ops.emplace_back(std::move(op.op));
               return true;
            }
            return false;
         });

         for(const auto& op : due_ops) {
            op();
         }
      }

      std::function<void()>& get_next_scheduled_operations() {
         auto next_op = std::min_element(
            m_deferred_ops.begin(), m_deferred_ops.end(), [](const Deferred_Operation& a, const Deferred_Operation& b) {
               return a.deadline_ms < b.deadline_ms;
            });

         if(next_op == m_deferred_ops.end()) {
            throw Botan_Tests::Test_Error("No scheduled operations");
         }

         return next_op->op;
      }

   private:
      struct Deferred_Operation {
            uint64_t deadline_ms;
            std::function<void()> op;
      };

      uint64_t m_now_ms = 0;
      std::vector<Deferred_Operation> m_deferred_ops;
};

class Timer_Operation final {
   public:
      Timer_Operation() = default;
      Timer_Operation(const Timer_Operation&) = delete;
      Timer_Operation& operator=(const Timer_Operation&) = delete;
      Timer_Operation(Timer_Operation&&) = default;
      Timer_Operation& operator=(Timer_Operation&&) = default;
      ~Timer_Operation() = default;

      std::function<void()> callback() {
         return [this]() { ++m_runs; };
      }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator bool() const { return m_runs > 0; }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator uint32_t() const { return m_runs; }

   private:
      uint32_t m_runs = 0;
};

class Retransmission_Test_Policy final : public Botan::TLS::Policy {
   public:
      Retransmission_Test_Policy(std::chrono::milliseconds initial_timeout,
                                 std::chrono::milliseconds maximum_timeout,
                                 std::optional<size_t> maximum_retransmissions) :
            m_initial_timeout(initial_timeout),
            m_maximum_timeout(maximum_timeout),
            m_maximum_retransmissions(maximum_retransmissions) {}

      size_t dtls_initial_timeout() const override { return m_initial_timeout.count(); }

      size_t dtls_maximum_timeout() const override { return m_maximum_timeout.count(); }

      std::optional<size_t> dtls_maximum_retransmissions() const override { return m_maximum_retransmissions; }

   private:
      std::chrono::milliseconds m_initial_timeout;
      std::chrono::milliseconds m_maximum_timeout;
      std::optional<size_t> m_maximum_retransmissions;
};

using namespace Botan;
using namespace Botan::TLS;
using namespace std::chrono_literals;

std::vector<Test::Result> singleshot_timer() {
   return {
      CHECK("deferred operation runs after deadline",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_true("token is valid", token);
               result.test_is_true("token is armed", token.armed());

               result.test_is_false("did not run yet", op);
               cb.advance(99ms);
               result.test_is_false("still didn't run yet", op);
               cb.advance(1ms);
               result.test_is_true("deferred operation ran", op);

               result.test_is_false("token is no longer valid", token);
               result.test_is_false("token is no longer armed", token.armed());
            }),

      CHECK("detached operation runs after deadline",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               SingleshotTimer::start_detached(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);
               cb.advance(99ms);
               result.test_is_false("still didn't run yet", op);
               cb.advance(1ms);
               result.test_is_true("deferred operation ran", op);
            }),

      CHECK("deferred operation runs only once, even when called multiple times",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);

               auto& scheduled_op = cb.get_next_scheduled_operations();
               scheduled_op();
               result.test_is_true("deferred operation ran", op);
               scheduled_op();
               result.test_u32_eq("deferred operation ran only once", op, 1);

               cb.advance(100ms);
               result.test_u32_eq("deferred operation didn't run after deadline", op, 1);
            }),

      CHECK("detached operation runs only once, even when called multiple times",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               SingleshotTimer::start_detached(cb, 100ms, op.callback());

               result.test_is_false("did not run yet", op);

               auto& scheduled_op = cb.get_next_scheduled_operations();
               scheduled_op();
               result.test_is_true("deferred operation ran", op);
               scheduled_op();
               result.test_u32_eq("deferred operation ran only once", op, 1);

               cb.advance(100ms);
               result.test_u32_eq("deferred operation didn't run after deadline", op, 1);
            }),

      CHECK("deferred operation does not re-run after throwing an exception",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               uint32_t runs = 0;

               auto token = SingleshotTimer::start(cb, 100ms, [&runs] {
                  ++runs;
                  throw TLS_Exception(Alert::None, "operation failed");
               });

               result.test_is_true("token is armed", token.armed());

               auto& scheduled_op = cb.get_next_scheduled_operations();
               result.test_throws<TLS_Exception>(
                  "operation threw an exception", "operation failed", [&] { scheduled_op(); });

               result.test_is_false("token is no longer armed", token.armed());

               scheduled_op();
               result.test_u32_eq("operation did not re-run when called again", runs, 1);

               cb.advance(100ms);
               result.test_u32_eq("operation did not re-run after the deadline", runs, 1);
            }),

      CHECK("detached operation does not re-run after throwing an exception",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               uint32_t runs = 0;

               SingleshotTimer::start_detached(cb, 100ms, [&runs] {
                  ++runs;
                  throw TLS_Exception(Alert::None, "operation failed");
               });

               auto& scheduled_op = cb.get_next_scheduled_operations();
               result.test_throws<TLS_Exception>(
                  "operation threw an exception", "operation failed", [&] { scheduled_op(); });

               scheduled_op();
               result.test_u32_eq("operation did not re-run when called again", runs, 1);

               cb.advance(100ms);
               result.test_u32_eq("operation did not re-run after the deadline", runs, 1);
            }),

      CHECK("deferred operation can be cancelled",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               auto token = SingleshotTimer::start(cb, 100ms, op.callback());

               result.test_is_true("token is valid", token);
               result.test_is_true("token is armed", token.armed());

               token.cancel();
               result.test_is_false("token is no longer valid", token);
               result.test_is_false("token is no longer armed", token.armed());

               cb.advance(100ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK("deferred operation is cancelled when token is destroyed",
            [&](Test::Result& result) {
               Timer_Callbacks cb;
               Timer_Operation op;

               {
                  auto token = SingleshotTimer::start(cb, 100ms, op.callback());

                  result.test_is_true("token is valid", token);
                  result.test_is_true("token is armed", token.armed());
               }

               cb.advance(100ms);
               result.test_is_false("deferred operation did not run", op);
            }),
   };
}

std::vector<Test::Result> retransmission_timer() {
   return {
      CHECK("retransmission timer is not armed on construction",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 3), cb);

               result.test_is_false("timer is not armed", timer.armed());

               cb->advance(1000ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK("cancelling a retransmission timer that does not run has no effect",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 3), cb);

               result.test_is_false("timer is not armed", timer.armed());

               timer.cancel();
               result.test_is_false("timer is still not armed", timer.armed());

               cb->advance(1000ms);
               result.test_is_false("deferred operation did not run", op);
            }),

      CHECK("starting a retransmission timer emits the deferred operation after the first timeout",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 3), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.armed());

               result.test_is_false("did not run yet", op);
               cb->advance(99ms);
               result.test_is_false("still didn't run yet", op);
               cb->advance(1ms);
               result.test_u32_eq("deferred operation ran once", op, 1);

               result.test_is_true("timer re-armed for retransmission", timer.armed());
            }),

      CHECK("retransmission timer re-emits with exponential backoff up to the maximum timeout",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, std::nullopt), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);

               // timeout doubled: 100ms -> 200ms
               cb->advance(199ms);
               result.test_u32_eq("did not retransmit before the doubled timeout", op, 1);
               cb->advance(1ms);
               result.test_u32_eq("second retransmission ran", op, 2);

               // timeout doubled again but capped: 400ms -> 250ms
               cb->advance(249ms);
               result.test_u32_eq("did not retransmit before the capped timeout", op, 2);
               cb->advance(1ms);
               result.test_u32_eq("third retransmission ran", op, 3);

               // timeout stays capped at 250ms
               cb->advance(249ms);
               result.test_u32_eq("did not retransmit before the capped timeout", op, 3);
               cb->advance(1ms);
               result.test_u32_eq("fourth retransmission ran", op, 4);

               result.test_is_true("timer is still armed", timer.armed());
            }),

      CHECK("retransmission timer eventually times out with an exception",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, 2), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               cb->advance(200ms);
               result.test_u32_eq("second retransmission ran", op, 2);

               result.test_throws<TLS_Exception>("timer gave up after the maximum number of retransmissions",
                                                 "DTLS handshake timed out: maximum retransmissions exceeded",
                                                 [&] { cb->advance(250ms); });
               result.test_u32_eq("no further retransmission was emitted", op, 2);
               result.test_is_false("timer is no longer armed after giving up", timer.armed());

               // a new flight can still be sent after the previous one timed out
               timer.start(op.callback());
               result.test_is_true("timer is armed after restart", timer.armed());

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", op, 2);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the initial timeout", op, 3);
            }),

      CHECK("restarting a retransmission timer resets the exponential backoff and replaces the operation",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;
               Timer_Operation restarted_op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, std::nullopt), cb);

               timer.start(op.callback());
               cb->advance(100ms);
               cb->advance(200ms);
               result.test_u32_eq("two retransmissions ran", op, 2);
               result.test_is_true("timer is armed", timer.armed());

               // restart (with a new operation) while the backed-off timer (250ms) is still pending
               timer.start(restarted_op.callback());
               result.test_is_true("timer is armed after restart", timer.armed());

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", restarted_op, 0);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the reset initial timeout", restarted_op, 1);

               // backoff starts over: 100ms -> 200ms
               cb->advance(199ms);
               result.test_u32_eq("did not retransmit before the doubled timeout", restarted_op, 1);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the reset doubled timeout", restarted_op, 2);

               result.test_u32_eq("previous operation was never invoked again", op, 2);
               result.test_is_true("timer is still armed", timer.armed());
            }),

      CHECK("destroying a running retransmission timer stops further retransmissions",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               {
                  RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, std::nullopt), cb);

                  timer.start(op.callback());
                  result.test_is_true("timer is armed", timer.armed());

                  cb->advance(100ms);
                  result.test_u32_eq("first retransmission ran", op, 1);
                  result.test_is_true("timer is still armed", timer.armed());
               }

               cb->advance(1000ms);
               result.test_u32_eq("no further retransmissions ran", op, 1);
            }),

      CHECK("cancelling a running retransmission timer stops further retransmissions",
            [&](Test::Result& result) {
               auto cb = std::make_shared<Timer_Callbacks>();
               Timer_Operation op;

               RetransmissionTimer timer(Retransmission_Test_Policy(100ms, 250ms, std::nullopt), cb);

               timer.start(op.callback());
               result.test_is_true("timer is armed", timer.armed());

               cb->advance(100ms);
               result.test_u32_eq("first retransmission ran", op, 1);
               result.test_is_true("timer is still armed", timer.armed());

               timer.cancel();
               result.test_is_false("timer is no longer armed", timer.armed());

               cb->advance(1000ms);
               result.test_u32_eq("no further retransmissions ran", op, 1);

               // restarting after a cancel starts with the initial timeout again
               timer.start(op.callback());
               result.test_is_true("timer is armed after restart", timer.armed());

               cb->advance(99ms);
               result.test_u32_eq("did not retransmit before the initial timeout", op, 1);
               cb->advance(1ms);
               result.test_u32_eq("retransmission ran after the initial timeout", op, 2);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "dtls_timers", singleshot_timer, retransmission_timer);

}  // namespace Botan_Tests

#endif
