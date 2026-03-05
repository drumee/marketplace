// File: service/payment.js
// Purpose: Stripe payment service with webhook handling

const { Entity } = require('@drumee/server-core');
const { toArray, Attr, Cache, Mariadb, RedisStore, Events, sysEnv } = require('@drumee/server-essentials');
const { resolve } = require('path');
const { readFileSync } = require('jsonfile');
const Stripe = require('stripe');
const { credential_dir } = sysEnv();
const {
  DENIED,
} = Events;
const PlanMapping = {
  year: {
    100: "Storage Bundle 100Y",
    200: "Storage Bundle 200Y",
    500: "Storage Bundle 500Y",
    1000: "Storage Bundle 1000Y"
  },
  moth: {
    100: "Storage Bundle 100M",
    200: "Storage Bundle 200M",
    500: "Storage Bundle 500M",
    1000: "Storage Bundle 1000M",
  }
}

class Payment extends Entity {

  /**
   * Initialize payment service
   * - Load payment hub configuration
   * - Connect to payment database
   * - Initialize Stripe SDK
   */
  initialize(opt) {
    super.initialize(opt);

    this.conf = JSON.parse(Cache.getSysConf('payment_conf'));
    if (!this.conf || !this.conf.db_name) {
      throw new Error('[PAYMENT] payment_conf not found in sys_conf. Please run setup.');
    }


    this.paymentDb = new Mariadb({ name: this.conf.db_name });
    // this.once(DENIED, () => {
    //   this.paymentDb.end()
    //   this.debug('[PAYMENT] DENIED end:of:session', this.paymentDb);
    // })
    // this.session.once("end:of:session", () => {
    //   this.paymentDb.end()
    //   this.debug('[PAYMENT] end:of:session', this.paymentDb);
    // })

    this._initializeStripe();

    this.debug('[PAYMENT] Service initialized');
    this.debug(`[PAYMENT] Hub: ${this.conf.hub_name}, DB: ${this.conf.db_name}`);
  }


  /**
   * Initialize Stripe SDK with credentials
   * @private
   */
  _initializeStripe() {
    try {
      const keyPath = resolve(credential_dir, 'stripe/info.json');

      const creds = readFileSync(keyPath);

      if (!creds || !creds.secret_key || !creds.webhook_secret) {
        throw new Error('Invalid credential format. Required: secret_key, webhook_secret');
      }

      this.stripe = Stripe(creds.secret_key);
      this.webhookSecret = creds.webhook_secret;
      this.publishableKey = creds.publishable_key;

      this.debug('[PAYMENT] Stripe SDK initialized');

    } catch (e) {
      this.warn('[PAYMENT] Failed to load Stripe credentials:', e.message);
      this.warn('[PAYMENT] Create file: {credential_dir}/stripe/info.json');
      this.warn('[PAYMENT] Format: {"secret_key": "sk_...", "webhook_secret": "whsec_...", "publishable_key": "pk_..."}');
      // Don't throw - allow service to start but webhook/payment will fail
    }
  }

  /**
 *
 */
  async sendHtml(data, tpl) {
    const main_domain = sysEnv()
    let html = readFileSync(tpl);
    html = String(html).trim().toString();
    const content = template(html)(data);
    this.output.set_header(
      "Cache-Control",
      "no-cache, no-store, must-revalidate"
    );

    this.output.set_header("Access-Control-Allow-Origin", `*.${main_domain}`);
    this.output.set_header("Pragma", "no-cache");
    this.output.html(content);
  }


  /**
   * Send payment data via WebSocket
   * @param {string} service - Service name for WebSocket event
   * @param {object} args - Data to send
   * @param {string} userId - Target user ID (optional, defaults to this.uid)
   */
  async sendPaymentData(service, args, userId = null) {
    const targetUserId = userId || this.uid;
    let payload;
    let recipients = await this.yp.await_proc("user_sockets", targetUserId);
    for (let r of toArray(recipients)) {
      payload = this.payload(args, { service });
      await RedisStore.sendData(payload, r);
    }

    this.debug(`[PAYMENT] WebSocket sent to user ${targetUserId}, service: ${service}`);
  }

  /**
   * Parse quota_category JSON safely
   * @private
   * @param {string|object} raw - Raw quota_category from database
   * @returns {object} Parsed quota category with fallback to default
   */
  _parseQuotaCategory(raw) {
    try {
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;

      // Validate structure
      if (!parsed || typeof parsed !== 'object') {
        this.warn('[PAYMENT] Invalid quota_category structure:', raw);
        return { category: 'default' };
      }

      return parsed;
    } catch (e) {
      this.warn('[PAYMENT] Failed to parse quota_category:', e.message, 'Raw:', raw);
      return { category: 'default' };
    }
  }

  /** To be replaced by checkout method
   * API: Create Payment Intent
   * Endpoint: POST /payment.create_payment_intent
   * 
   * Input: 
   * - amount: Amount in cents (e.g., 1000 = $10.00)
   * - currency: ISO currency code (default: usd)
   * - description: Payment description (optional)
   * - metadata: Additional metadata (optional)
   * 
   * Output:
   * - client_secret: For confirming payment on client
   * - payment_intent_id: Stripe Payment Intent ID
   * - publishable_key: Stripe publishable key for client
   */
  async create_payment_intent() {
    try {
      if (!this.stripe) {
        return this.output.data({
          status: 'error',
          error: 'stripe_not_configured',
          message: 'Stripe is not configured on server'
        });
      }

      // Get and validate inputs
      const amount = parseInt(this.input.get('amount'));
      const currency = this.input.get('currency') || 'usd';
      const description = this.input.get('description') || 'Drumee Payment';
      const metadata = this.input.get('metadata') || {};

      // Validate amount
      if (!amount || amount <= 0) {
        return this.output.data({
          status: 'error',
          error: 'invalid_amount',
          message: 'Amount must be a positive integer (in cents)'
        });
      }

      // Validate currency (ISO 4217)
      if (!/^[a-z]{3}$/i.test(currency)) {
        return this.output.data({
          status: 'error',
          error: 'invalid_currency',
          message: 'Currency must be a 3-letter ISO code (e.g., usd, eur)'
        });
      }

      // Add system metadata
      const enrichedMetadata = {
        ...metadata,
        drumate_id: this.uid,
        hub_id: this.input.get(Attr.hub_id) || 'unknown',
        created_via: 'drumee_api',
        timestamp: Math.floor(Date.now() / 1000)
      };

      this.debug(`[PAYMENT] Creating payment intent: ${amount} ${currency}`);

      // Create Stripe Payment Intent
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount: amount,
        currency: currency.toLowerCase(),
        description: description,
        automatic_payment_methods: { enabled: true },
        metadata: enrichedMetadata
      });

      this.debug(`[PAYMENT] Payment intent created: ${paymentIntent.id}`);

      // Log to database (non-blocking)
      this._logPaymentIntent(paymentIntent).catch(err => {
        this.warn('[PAYMENT] Failed to log payment intent:', err.message);
      });
      return this.output.data({
        status: 'ok',
        client_secret: paymentIntent.client_secret,
        payment_intent_id: paymentIntent.id,
        publishable_key: this.publishableKey
      });

    } catch (error) {
      this.warn('[PAYMENT] Error creating payment intent:', error.message);
      return this.output.data({
        status: 'error',
        error: 'payment_intent_creation_failed',
        message: error.message
      });
    }
  }

  /**
   * API: Checkout
   * Endpoint: POST /payment.checkout
   * 
   * Input:
   * - plan: Plan name (e.g., "pro")
   * - interval: 'month' or 'year'
   * - seats: Number of seats (minimum 5 for Pro plan)
   * 
   * Output:
   * - sessionId: Stripe Checkout Session ID
   * - url: URL to redirect user to Stripe Checkout page
   * 
   * Cart nuber for testing:
   * - Success: 4242 4242 4242 4242
   * - Authentication required: 4000 0025 0000 3155
   * - Decline: 4000 0000 0000 9995
   */
  async checkout() {
    try {
      if (!this.stripe) {
        return this.output.data({
          status: 'error',
          error: 'stripe_not_configured',
          message: 'Stripe is not configured on server'
        });
      }

      // Get parameters from query params or form data
      // const plan = this.input.get('plan');
      // const interval = this.input.get('interval') || 'month';
      // const seats = parseInt(this.input.get('seats')) || 5;
      const {
        interval,
        bundleStorage,
        plan,
        seats,
        storage,
        extraSeats
      } = this.input.need('payment');

      const billingPeriod = interval;
      this.debug('[PAYMENT] Checkout request:', { plan, interval, seats, uid: this.uid });

      // Validation
      if (!plan || plan.trim() === '') {
        this.warn('[PAYMENT] Missing plan parameter');
        return this.output.data({
          status: 'error',
          message: 'Plan parameter is required'
        });
      }

      if (!['month', 'year'].includes(interval)) {
        this.warn('[PAYMENT] Invalid interval:', interval);
        return this.output.data({
          status: 'error',
          message: 'Interval must be "month" or "year"'
        });
      }

      // Pro plan requires minimum 5 seats (base package)
      const baseSeats = 5;
      if (seats < baseSeats) {
        this.warn('[PAYMENT] Invalid seats:', seats);
        return this.output.data({
          status: 'error',
          message: `Pro plan requires minimum ${baseSeats} seats`
        });
      }


      //Look up price ID from plan_mapping
      // const billingPeriod = interval === 'year' ? 'yearly' : 'monthly';

      const planInfo = await this.paymentDb.await_proc(
        'get_price_for_plan',
        plan,
        billingPeriod
      );

      this.debug('[PAYMENT] 288 Using base price ID:', { plan, billingPeriod, planInfo });

      if (!planInfo || !planInfo.stripe_price_id) {
        this.warn('[PAYMENT] No price found for plan:', plan, billingPeriod);
        return this.output.data({
          status: 'error',
          message: `Plan "${plan}" (${billingPeriod}) not found. Please sync plans from Stripe.`
        });
      }

      const basePriceId = planInfo.stripe_price_id;

      this.debug('[PAYMENT] 299 Using base price ID:', basePriceId, 'for plan:', plan);

      const lineItems = [
        {
          price: basePriceId,  // Pro base: $16.99/month (includes 5 seats)
          quantity: 1,
          metadata: {
            drumate_id: this.uid,
            plan,
            base_seats: baseSeats,
            storage
          }
        }
      ];

      // Add additional seats if needed
      if (extraSeats > 0) {
        this.debug('[PAYMENT] Looking up additional seat pricing...', { extraSeats });

        const additionalSeatInfo = await this.paymentDb.await_proc(
          'get_price_for_plan',
          'Additional Seat',
          interval
        );

        if (!additionalSeatInfo || !additionalSeatInfo.stripe_price_id) {
          this.warn('[363] Additional Seat price not found for:', interval);
          return this.output.data({
            status: 'error',
            message: `Additional Seat pricing not configured. Please create "Additional Seat" product in Stripe.`
          });
        }

        const additionalSeatPriceId = additionalSeatInfo.stripe_price_id;
        this.debug('[PAYMENT] Using additional seat price ID:', additionalSeatPriceId, 'for', extraSeats, 'seats');

        lineItems.push({
          price: additionalSeatPriceId,  // $5/seat/month
          quantity: extraSeats,
          metadata: {
            drumate_id: this.uid,
            additional_seats: extraSeats,
            interval
          }
        });
      }
      // Add Bundle storage
      let bundle = PlanMapping[interval]
      if (bundle && bundle[bundleStorage]) {
        this.debug('[PAYMENT] Looking up additional seat pricing...');

        const additionalSeatInfo = await this.paymentDb.await_proc(
          'get_price_for_plan',
          bundle[bundleStorage],
          interval
        );

        if (!additionalSeatInfo || !additionalSeatInfo.stripe_price_id) {
          this.warn('[395] bundleStorage found for:', bundle[bundleStorage], interval);
          return this.output.data({
            status: 'error',
            message: `Additional Seat pricing not configured. Please create "Additional Seat" product in Stripe.`
          });
        }

        const additionalSeatPriceId = additionalSeatInfo.stripe_price_id;
        this.debug('[PAYMENT] Using additional seat price ID:', additionalSeatPriceId, 'for', extraSeats, 'seats');

        lineItems.push({
          price: additionalSeatPriceId,  // $5/seat/month
          quantity: 1,
          metadata: {
            drumate_id: this.uid,
            bundleStorage,
            interval,
            extraSeats,

          }
        });
      }
      // Dynamic service location based on endpoint 
      const svc_base = `${this.input.homepath()}svc`;
      let customer_email = this.user.get(Attr.profile)?.email;
      let opt = {
        payment_method_types: ['card'],
        customer_email,
        line_items: lineItems,
        mode: 'subscription',
        success_url: `${svc_base}/payment.success`,
        cancel_url: `${svc_base}/payment.aborted`,
        metadata: {
          drumate_id: this.uid,
          plan,
          total_seats: seats,
          interval,
          bundleStorage,
          plan,
          seats,
          storage,
          extraSeats
        },
        subscription_data: {
          metadata: {
            drumate_id: this.uid,
            plan,
            interval,
            bundleStorage,
            total_seats: seats,
            plan,
            seats,
            storage,
            extraSeats
          }
        },
      }

      this.debug('[PAYMENT] Checkout Creating session with:', this.user.get(Attr.profile), Attr.profile, opt);

      const session = await this.stripe.checkout.sessions.create(opt);

      this.debug('[PAYMENT] Line items:', lineItems.length);
      this.debug('[PAYMENT] Base seats:', baseSeats, '+ Extra seats:', extraSeats, '= Total:', seats);

      return this.output.data({
        sessionId: session.id,
        url: session.url
      });

    } catch (error) {
      this.warn('[PAYMENT] Checkout error:', error.message);
      return this.output.data({
        status: 'error',
        message: error.message
      });
    }
  }

  /* API: Payment Aborted/Cancelled
   * Endpoint: POST /payment.aborted
   * 
   * Called by stripe when:
   * - User cancels checkout session
   * - Session expires
   * - Payment fails
   * 
   * Redirect to user payment.aborted
   * */
  async aborted() {
    try {
      // Get session ID from query params (Stripe sends this)
      const sessionId = this.input.get('session_id');

      this.debug(`[PAYMENT] Payment aborted/cancelled, session: ${sessionId}`);

      // Optional: Log the cancellation
      if (sessionId) {
        try {
          // Retrieve session details from Stripe
          const session = await this.stripe.checkout.sessions.retrieve(sessionId);

          // Log cancellation to database
          await this.paymentDb.await_proc(
            'log_webhook_event',
            `cancel_${sessionId}`,           // event_id
            'checkout.session.cancelled',    // event_type
            JSON.stringify({
              session_id: sessionId,
              customer: session.customer,
              amount_total: session.amount_total,
              metadata: session.metadata,
              cancelled_at: Math.floor(Date.now() / 1000)
            }),                              // event_data
            Math.floor(Date.now() / 1000)    // ctime
          );

          this.debug(`[PAYMENT] Logged cancellation for session ${sessionId}`);
        } catch (err) {
          this.warn('[PAYMENT] Failed to log cancellation:', err.message);
        }
      }

      // Redirect user to frontend with cancellation message
      const redirectUrl = `https://${this.input.host()}/#/payment-cancelled`;
      return this.output.redirect(redirectUrl);

    } catch (error) {
      this.warn('[PAYMENT] Error in aborted handler:', error.message);
      // Fallback redirect
      const redirectUrl = `https://${this.input.host()}/#/payment-error`;
      return this.output.redirect(redirectUrl);
    }
  }

  /**
  * API: Payment Success Page
  * Endpoint: GET /payment.success
  * 
  * Shows success page after payment completion
  */
  async success() {
    try {
      this.debug('[PAYMENT] Displaying payment success page');

      const fs = require('fs');
      const tpl = resolve(__dirname, './templates/payment-completed.html');
      const html = fs.readFileSync(tpl, 'utf8');

      this.output.set_header("Content-Type", "text/html; charset=utf-8");
      this.output.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
      this.output.set_header("Pragma", "no-cache");

      return this.output.html(html);

    } catch (error) {
      this.warn('[PAYMENT] Error loading success page:', error.message);

      // Simple fallback message
      return this.output.text('Payment completed successfully! Thank you. You can close this window now.');
    }
  }

  /**
   * API: Handle Stripe Webhook
   * Endpoint: POST /payment.webhook
   * 
   * This endpoint receives events from Stripe and must:
   * 1. Verify webhook signature (CRITICAL for security)
   * 2. Log event to database
   * 3. Process event based on type
   * 4. Return 200 OK quickly (Stripe retries if timeout)
   */
  async webhook() {
    try {
      if (!this.stripe || !this.webhookSecret) {
        this.warn('[PAYMENT] Webhook called but Stripe not configured');
        return this.output.data({
          status: 'error',
          message: 'Stripe not configured on server'
        });
      }

      // Get signature and raw body
      const signature = this.input.headers()['stripe-signature'];
      const rawBody = this.input.rawString(); // MUST be raw, not parsed JSON

      if (!signature) {
        this.warn('[PAYMENT] Webhook missing stripe-signature header');
        return this.output.text('Payment completed! You can close this window.');
      }

      if (!rawBody) {
        // this.warn('[PAYMENT] Webhook missing body');
        // const tpl = resolve(__dirname, './templates/payment-completed.html');
        // this.sendHtml({}, tpl)
        // return
        return this.output.data({
          status: 'error',
          message: 'Missing body'
        });
      }

      // CRITICAL: Verify webhook signature
      let event;
      try {
        event = this.stripe.webhooks.constructEvent(
          rawBody,
          signature,
          this.webhookSecret
        );
      } catch (err) {
        this.warn(`[PAYMENT] Webhook signature verification failed: ${err.message}`);
        return this.output.data({
          status: 'error',
          message: 'Invalid signature'
        });
      }

      this.debug(`[PAYMENT] Webhook received: ${event.type} (${event.id})`);

      // Check for duplicate event (idempotency)
      const isDuplicate = await this._checkDuplicateEvent(event.id);
      if (isDuplicate) {
        this.debug(`[PAYMENT] Duplicate event ${event.id}, skipping`);
        return this.output.data({ received: true, duplicate: true });
      }

      // Log event to database (non-blocking)
      this._logWebhookEvent(event).catch(err => {
        this.warn('[PAYMENT] Failed to log webhook event:', err.message);
      });

      // Process event asynchronously (don't block webhook response)
      this._processWebhookEvent(event).catch(err => {
        this.warn(`[PAYMENT] Error processing webhook ${event.type}:`, err.message);
      });

    } catch (error) {
      this.warn('[PAYMENT] Webhook handler exception:', error.message);
      return this.output.data({
        status: 'error',
        message: 'Internal error'
      });
    }
    // Stripe expects fast response
    return this.output.text('{ "received": true }');
  }

  /**
   * Check if webhook event already processed (prevent duplicates)
   * @private
   */
  async _checkDuplicateEvent(eventId) {
    try {
      const result = await this.paymentDb.await_query(
        'SELECT id FROM webhook_logs WHERE event_id = ? LIMIT 1',
        eventId
      );
      return toArray(result).length > 0;
    } catch (error) {
      this.warn('[PAYMENT] Error checking duplicate event:', error.message);
      return false;
    }
  }

  /**
   * Log payment intent creation to database
   * @private
   */
  async _logPaymentIntent(paymentIntent) {
    await this.paymentDb.await_proc(
      'create_or_update_transaction',
      paymentIntent.id,
      paymentIntent.customer || null,
      paymentIntent.metadata?.drumate_id || null,
      paymentIntent.amount,
      paymentIntent.currency,
      paymentIntent.status,
      paymentIntent.payment_method || null,
      JSON.stringify(paymentIntent.metadata || {}),
      Math.floor(Date.now() / 1000),                 // ctime
      Math.floor(Date.now() / 1000)                  // mtime
    );
  }

  /**
   * Log webhook event to database
   * Note: Full event logging is required for audit trail and dispute resolution
   * @private
   */
  async _logWebhookEvent(event) {
    await this.paymentDb.await_proc(
      'log_webhook_event',
      event.id,                          // event_id
      event.type,                        // event_type
      JSON.stringify(event),             // event_data
      Math.floor(Date.now() / 1000)      // ctime
    );
  }

  /**
   * Process webhook event based on type
   * @private
   */
  async _processWebhookEvent(event) {
    const { type, data } = event;
    const object = data.object;

    try {
      switch (type) {
        // Checkout Session Events
        case 'checkout.session.completed':
          await this._handleCheckoutCompleted(object);
          break;

        case 'checkout.session.expired':
          await this._handleCheckoutExpired(object);
          break;

        case 'checkout.session.async_payment_succeeded':
          await this._handleCheckoutAsyncSuccess(object);
          break;

        case 'checkout.session.async_payment_failed':
          await this._handleCheckoutAsyncFailed(object);
          break;

        // Payment Intent Events
        case 'payment_intent.succeeded':
          await this._handlePaymentSuccess(object);
          break;

        case 'payment_intent.payment_failed':
          await this._handlePaymentFailed(object);
          break;

        case 'payment_intent.canceled':
          await this._handlePaymentCanceled(object);
          break;

        // Charge Events
        case 'charge.succeeded':
          await this._handleChargeSuccess(object);
          break;

        case 'charge.failed':
          await this._handleChargeFailed(object);
          break;

        case 'charge.refunded':
          await this._handleChargeRefunded(object);
          break;

        case 'charge.dispute.created':
          await this._handleChargeDispute(object);
          break;

        // Customer Events customer.subscription.updated 
        case 'customer.created':
        case 'customer.updated':
          await this._handleCustomerChanged(object);
          break;

        case 'customer.deleted':
          await this._handleCustomerDeleted(object);
          break;

        // Subscription Events
        case 'customer.subscription.created':
        case 'customer.subscription.updated':
          await this._handleSubscriptionChanged(object);
          break;

        case 'customer.subscription.deleted':
          await this._handleSubscriptionDeleted(object);
          break;

        // Invoice Events
        case 'invoice.paid':
          await this._handleInvoicePaid(object);
          break;

        case 'invoice.payment_failed':
          await this._handleInvoiceFailed(object);
          break;

        case 'invoice.payment_action_required':
          await this._handleInvoiceActionRequired(object);
          break;

        case 'invoice.payment_succeeded':
          this.debug(`[PAYMENT] SUCESS: ${type}`, object);
          break;

        default:
          this.debug(`[PAYMENT] Unhandled event type: ${type}`);
      }

      await this.paymentDb.await_proc('mark_event_processed', event.id, 1, null);

    } catch (error) {
      this.warn(`[PAYMENT] Error processing ${type}:`, error.message);

      await this.paymentDb.await_proc(
        'mark_event_processed',
        event.id,
        0,
        error.message
      );
    }
    // let user = await this.yp.await_proc('get_user', this.uid)
    // this.sendPaymentData(type, { user, data })
  }

  /**
   * Handle checkout.session.completed event
   * Main success event for checkout sessions
   */
  async _handleCheckoutCompleted(session) {
    try {
      this.debug('[PAYMENT] Checkout session completed:', session.id);

      const customerId = session.customer;
      const subscriptionId = session.subscription;
      const drumateId = session.metadata?.drumate_id || session.client_reference_id;

      if (!drumateId) {
        this.warn('[PAYMENT][542] No drumate_id in session metadata:', session);
        console.log('Full session object:', JSON.stringify(session, null, 2));
        console.log('Metadata:', session.metadata); // Should have data
        return;
      }

      // For subscription mode, category update happens in invoice.paid
      // For one-time payment mode, update category here
      if (session.mode === 'payment') {
        const lineItems = await this.stripe.checkout.sessions.listLineItems(session.id);
        const priceId = lineItems.data[0]?.price?.id;

        if (priceId) {
          const planInfo = await this.paymentDb.await_proc('get_plan_by_price', priceId);

          if (planInfo && planInfo.stripe_price_id) {
            const plan = planInfo;

            const quotaCategory = this._parseQuotaCategory(plan.quota_category);
            const categoryValue = quotaCategory?.category || 'default';

            await this.yp.await_proc('drumate_update_profile', drumateId, JSON.stringify({
              category: categoryValue,
              billing_cycle: plan.billing_period
            }));

            this.debug(`[PAYMENT] Updated drumate ${drumateId} to category: ${categoryValue}`);
          }
        }
      }

      this.debug('[PAYMENT] Checkout completed successfully for session:', session.id);

    } catch (error) {
      this.error('[PAYMENT] Error handling checkout completion:', error);
      throw error;
    }
  }

  /**
   * Handle checkout.session.expired
   */
  async _handleCheckoutExpired(session) {
    try {
      this.debug('[PAYMENT] Checkout session expired:', session.id);

      // Log expiration for tracking
      const drumateId = session.metadata?.drumate_id || session.client_reference_id;

      if (drumateId) {
        this.debug(`[PAYMENT] Session expired for drumate ${drumateId}, amount: ${session.amount_total}`);

        // Send WebSocket notification
        try {
          const userData = await this.yp.await_proc('get_user', drumateId);
          await this.sendPaymentData('payment.checkout_expired', {
            ...userData,
            session_id: session.id,
            amount: session.amount_total,
            expired_at: Math.floor(Date.now() / 1000)
          }, drumateId);
        } catch (wsError) {
          this.warn('[PAYMENT] Failed to send expiration notification:', wsError.message);
        }
      }
    } catch (error) {
      this.warn('[PAYMENT] Error handling checkout expiration:', error.message);
    }
  }

  /**
   * Handle checkout.session.async_payment_succeeded
   * For payments that complete after the checkout session (e.g., bank transfers)
   */
  async _handleCheckoutAsyncSuccess(session) {
    try {
      this.debug('[PAYMENT] Async payment succeeded:', session.id);

      const drumateId = session.metadata?.drumate_id || session.client_reference_id;

      if (!drumateId) {
        this.warn('[PAYMENT][609] No drumate_id in async payment session:', session.id);
        return;
      }

      // Similar to checkout.session.completed
      if (session.mode === 'payment') {
        const lineItems = await this.stripe.checkout.sessions.listLineItems(session.id);
        const priceId = lineItems.data[0]?.price?.id;

        if (priceId) {
          const planInfo = await this.paymentDb.await_proc('get_plan_by_price', priceId);

          if (planInfo && planInfo.stripe_price_id) {
            const plan = planInfo;

            const quotaCategory = this._parseQuotaCategory(plan.quota_category);
            const categoryValue = quotaCategory?.category || 'default';

            await this.yp.await_proc('drumate_update_profile', drumateId, JSON.stringify({
              category: categoryValue,
              billing_cycle: plan.billing_period
            }));

            this.debug(`[PAYMENT] Async payment: Updated drumate ${drumateId} to category: ${categoryValue}`);
          }
        }
      }

    } catch (error) {
      this.error('[PAYMENT] Error handling async payment success:', error);
      throw error;
    }
  }

  /**
   * Handle checkout.session.async_payment_failed
   */
  async _handleCheckoutAsyncFailed(session) {
    try {
      this.debug('[PAYMENT] Async payment failed:', session.id);

      const drumateId = session.metadata?.drumate_id || session.client_reference_id;

      if (drumateId) {
        this.warn(`[PAYMENT] Async payment failed for drumate ${drumateId}, session: ${session.id}`);

        // Send WebSocket notification
        try {
          const userData = await this.yp.await_proc('get_user', drumateId);
          await this.sendPaymentData('payment.async_payment_failed', {
            ...userData,
            session_id: session.id,
            failed_at: Math.floor(Date.now() / 1000)
          }, drumateId);
        } catch (wsError) {
          this.warn('[PAYMENT] Failed to send async failure notification:', wsError.message);
        }
      }
    } catch (error) {
      this.warn('[PAYMENT] Error handling async payment failure:', error.message);
    }
  }

  /**
   * Handle successful payment
   * @private
   */
  async _handlePaymentSuccess(paymentIntent) {
    this.debug(`[PAYMENT] Payment succeeded: ${paymentIntent.id}, amount: ${paymentIntent.amount}`);

    await this.paymentDb.await_proc(
      'create_or_update_transaction',
      paymentIntent.id,
      paymentIntent.customer,
      paymentIntent.metadata?.drumate_id || null,
      paymentIntent.amount,
      paymentIntent.currency,
      'succeeded',
      paymentIntent.payment_method,
      JSON.stringify(paymentIntent.metadata || {}),
      Math.floor(Date.now() / 1000),
      Math.floor(Date.now() / 1000)
    );
    // let recipients = await this.yp.await_proc("entity_sockets", this.uid);
    // let user = await this.yp.await_proc("get_user", this.uid);
    // await RedisStore.sendData(this.payload({ paid: 1, user }), recipients);
    // TODO: Add business logic
    // - Update user subscription
    // - Grant premium access
    // - Send confirmation email
    // - Trigger analytics event
  }

  /**
   * Handle failed payment
   * @private
   */
  async _handlePaymentFailed(paymentIntent) {
    this.debug(`[PAYMENT] Payment failed: ${paymentIntent.id}`);

    await this.paymentDb.await_proc(
      'create_or_update_transaction',
      paymentIntent.id,
      paymentIntent.customer,
      paymentIntent.metadata?.drumate_id || null,
      paymentIntent.amount,
      paymentIntent.currency,
      'failed',
      paymentIntent.payment_method,
      JSON.stringify(paymentIntent.metadata || {}),
      Math.floor(Date.now() / 1000),
      Math.floor(Date.now() / 1000)
    );

    // Send WebSocket notification
    const drumateId = paymentIntent.metadata?.drumate_id;
    if (drumateId) {
      try {
        const userData = await this.yp.await_proc('get_user', drumateId);
        await this.sendPaymentData('payment.payment_failed', {
          ...userData,
          payment_intent_id: paymentIntent.id,
          amount: paymentIntent.amount,
          currency: paymentIntent.currency,
          failed_at: Math.floor(Date.now() / 1000)
        }, drumateId);
      } catch (wsError) {
        this.warn('[PAYMENT] Failed to send payment failure notification:', wsError.message);
      }
    }
  }

  /**
   * Handle canceled payment
   * @private
   */
  async _handlePaymentCanceled(paymentIntent) {
    this.debug(`[PAYMENT] Payment canceled: ${paymentIntent.id}`);

    await this.paymentDb.await_proc(
      'create_or_update_transaction',
      paymentIntent.id,
      paymentIntent.customer,
      paymentIntent.metadata?.drumate_id || null,
      paymentIntent.amount,
      paymentIntent.currency,
      'canceled',
      null,  // payment_method
      JSON.stringify(paymentIntent.metadata || {}),
      Math.floor(Date.now() / 1000),
      Math.floor(Date.now() / 1000)
    );
  }

  /**
   * Handle charge success
   * @private
   */
  async _handleChargeSuccess(charge) {
    this.debug(`[PAYMENT] Charge succeeded: ${charge.id}`);
  }

  /**
   * Handle charge failed
   * @private
   */
  async _handleChargeFailed(charge) {
    this.debug(`[PAYMENT] Charge failed: ${charge.id}`);
  }

  /**
   * Handle charge refunded
   * @private
   */
  async _handleChargeRefunded(charge) {
    this.debug(`[PAYMENT] Charge refunded: ${charge.id}, amount: ${charge.amount_refunded}`);

    await this.paymentDb.await_proc(
      'update_transaction_status',
      charge.payment_intent,                                    // stripe_payment_intent_id
      'refunded',                                               // status
      JSON.stringify({ refund_amount: charge.amount_refunded }), // metadata
      Math.floor(Date.now() / 1000)                             // mtime
    );
  }

  /**
   * Handle charge dispute
   * @private
   */
  async _handleChargeDispute(dispute) {
    this.debug(`[PAYMENT] Charge dispute created: ${dispute.id}, charge: ${dispute.charge}`);

    // Log dispute for admin review
    this.warn(`[PAYMENT] DISPUTE: ${dispute.reason} - Amount: ${dispute.amount}`);

    // Optional: Send alert to admin
  }

  /**
   * Handle customer created/updated
   * @private
   */
  async _handleCustomerChanged(customer) {
    this.debug(`[PAYMENT] Customer changed: ${customer.id}`);

    await this.paymentDb.await_proc(
      'create_or_update_customer',
      customer.id,                                    // stripe_customer_id
      customer.metadata?.drumate_id || null,          // drumate_id
      customer.email,                                 // email
      customer.name,                                  // name
      JSON.stringify(customer.metadata || {}),        // metadata
      Math.floor(Date.now() / 1000),                  // ctime
      Math.floor(Date.now() / 1000)                   // mtime
    );
  }

  /**
   * Handle customer deleted
   * @private
   */
  async _handleCustomerDeleted(customer) {
    this.debug(`[PAYMENT] Customer deleted: ${customer.id}`);

    await this.paymentDb.await_proc('delete_customer', customer.id);
  }

  /**
   * Handle subscription created/updated
   * @private
   */
  async _handleSubscriptionChanged(subscription) {
    this.debug(`[PAYMENT] Subscription changed: ${subscription.id}, status: ${subscription.status}`);

    await this.paymentDb.await_proc(
      'create_or_update_subscription',
      subscription.id,                                // stripe_subscription_id
      subscription.customer,                          // stripe_customer_id
      subscription.metadata?.drumate_id || null,      // drumate_id
      subscription.items.data[0]?.price.id,           // plan_id
      subscription.status,                            // status
      subscription.current_period_start,              // current_period_start
      subscription.current_period_end,                // current_period_end
      subscription.cancel_at || 0,                    // cancel_at
      JSON.stringify(subscription.metadata || {}),    // metadata
      Math.floor(Date.now() / 1000),                  // ctime
      Math.floor(Date.now() / 1000)                   // mtime
    );
  }

  /**
   * Handle subscription deleted
   * @private
   */
  async _handleSubscriptionDeleted(subscription) {
    this.debug(`[PAYMENT] Subscription deleted: ${subscription.id}`);

    const drumateId = subscription.metadata?.drumate_id;

    await this.paymentDb.await_proc('delete_subscription', subscription.id);

    // Send WebSocket notification
    if (drumateId) {
      try {
        const userData = await this.yp.await_proc('get_user', drumateId);
        await this.sendPaymentData('payment.subscription_cancelled', {
          ...userData,
          subscription_id: subscription.id,
          cancelled_at: Math.floor(Date.now() / 1000)
        }, drumateId);
      } catch (wsError) {
        this.warn('[PAYMENT] Failed to send cancellation notification:', wsError.message);
      }
    }
  }

  /**
  * Handle invoice.paid event
  * - Save invoice to database
  * - Update drumate category to new plan planInfo
  * - Mark invoice as paid
  */
  async _handleInvoicePaid(invoice) {
    try {
      this.debug('[PAYMENT] Processing invoice.paid:', invoice);

      // Get drumate_id from correct sources
      const drumateId = invoice.metadata?.drumate_id
        || invoice.lines?.data?.[0]?.metadata?.drumate_id
        || invoice.subscription_details?.metadata?.drumate_id;

      if (!drumateId) {
        this.warn('[PAYMENT][853]No drumate_id in invoice metadata:', invoice);
        return;
      }

      const seats = parseInt(
        invoice.metadata?.total_seats
        || invoice.subscription_details?.metadata?.total_seats
        || 5
      );
      let disk = parseInt(
        invoice.metadata?.storage
        || invoice.subscription_details?.metadata?.storage
        || 20
      );
      // Get plan info from Stripe price ID
      const priceId = invoice.lines.data[0]?.price?.id;
      if (!priceId) {
        this.warn('[PAYMENT] No price ID in invoice:', invoice);
        return;
      }
      const planInfo = await this.paymentDb.await_proc('get_plan_by_price', priceId);
      if (!planInfo || !planInfo.stripe_price_id) {
        this.warn('[PAYMENT] No plan mapping found for price:', invoice, priceId);
        return;
      }

      const plan = planInfo;
      const now = Math.floor(Date.now() / 1000);

      // Extract category from JSON quota_category
      const quotaCategory = this._parseQuotaCategory(plan.quota_category);
      const categoryValue = quotaCategory?.category || 'default';
      let due_date = invoice.due_date || invoice.effective_at || now;
      // Save invoice to database
      await this.paymentDb.await_proc(
        'create_or_update_invoice',
        invoice.id,                                    // stripe_invoice_id
        invoice.customer,                              // stripe_customer_id
        drumateId,                                     // drumate_id
        invoice.subscription,                          // stripe_subscription_id
        invoice.payment_intent,                        // stripe_payment_intent_id
        invoice.number,                                // invoice_number
        invoice.amount_due,                            // amount_due (cents)
        invoice.amount_paid,                           // amount_paid (cents)
        invoice.currency,                              // currency
        'paid',                                        // status
        plan.plan_name,                                // plan_name
        JSON.stringify(plan.quota_category),           // quota_category
        plan.storage_quota,                            // storage_quota (bytes)
        plan.billing_period,                           // billing_period
        invoice.created,                               // invoice_date
        due_date,                                      // due_date
        invoice.status_transitions?.paid_at || now,    // paid_at
        invoice.period_start,                          // period_start
        invoice.period_end,                            // period_end
        invoice.invoice_pdf,                           // invoice_pdf
        invoice.hosted_invoice_url,                    // hosted_invoice_url
        JSON.stringify(invoice.metadata || {}),        // metadata
        invoice.created,                               // ctime
        now                                            // mtime
      );

      let drumate = await this.yp.await_proc('get_user', drumateId);
      await this.yp.await_proc('get_user', drumateId);
      let features = {
        seat: seats,
        history_length: planInfo.history_length || 7,
        disk: disk * 1000000000,
        organization: planInfo.organization || 1,
        billing_cycle: plan.billing_period,
        plan: categoryValue,
        tag: this.randomString()
      }
      let quota = await this.yp.await_proc('create_quota', drumate.domain_id, drumateId, planInfo.plan_name, features);
      // await this.yp.await_proc("create_payment", invoice.id, drumateId, plan.plan_name,
      //   invoice.subscription_details?.metadata
      // )
      this.debug("AAA:261", quota, Attr.profile, this.user.get(Attr.profile))

      this.debug(`[PAYMENT] Successfully updated drumate ${drumateId}:`);
      this.debug(`  - Category: ${categoryValue}`);
      this.debug(`  - Billing: ${plan.billing_period}`);
      this.debug(`  - Seats: ${seats}`);
      const userData = await this.yp.await_proc('get_user', drumateId);
      await this.sendPaymentData('payment.plan_updated', userData, drumateId);

    } catch (error) {
      this.error('[PAYMENT] Error handling invoice.paid:', error);
      throw error;
    }

  }

  /**
  * Handle invoice payment failed
  * - Save invoice with failed status
  * - Don't update drumate category
  * - Log for admin review 
  */
  async _handleInvoiceFailed(invoice) {
    try {
      this.debug('[PAYMENT] Processing invoice.payment_failed:', invoice.id);

      const drumateId = invoice.metadata?.drumate_id
        || invoice.lines?.data?.[0]?.metadata?.drumate_id
        || invoice.subscription_details?.metadata?.drumate_id;

      if (!drumateId) {
        this.warn('[PAYMENT][929]  No drumate_id in invoice metadata:', invoice);
        return;
      }

      // Get plan info (for logging purposes)
      const priceId = invoice.lines.data[0]?.price?.id;
      let plan = {
        plan_name: 'Unknown',
        quota_category: { category: 'default' },
        storage_quota: 0,
        billing_period: 'monthly'
      };

      if (priceId) {
        const planInfo = await this.paymentDb.await_proc('get_plan_by_price', priceId);
        if (planInfo && planInfo.stripe_price_id) {
          plan = planInfo;
        }
      }

      const now = Math.floor(Date.now() / 1000);

      // Save invoice with failed status
      await this.paymentDb.await_proc(
        'create_or_update_invoice',
        invoice.id,                                    // stripe_invoice_id
        invoice.customer,                              // stripe_customer_id
        drumateId,                                     // drumate_id
        invoice.subscription,                          // stripe_subscription_id
        invoice.payment_intent,                        // stripe_payment_intent_id
        invoice.number,                                // invoice_number
        invoice.amount_due,                            // amount_due (cents)
        0,                                             // amount_paid (0 for failed)
        invoice.currency,                              // currency
        'payment_failed',                              // status
        plan.plan_name,                                // plan_name
        JSON.stringify(plan.quota_category),           // quota_category
        plan.storage_quota,                            // storage_quota (bytes)
        plan.billing_period,                           // billing_period
        invoice.created,                               // invoice_date
        invoice.due_date,                              // due_date
        null,                                          // paid_at (NULL for failed)
        invoice.period_start,                          // period_start
        invoice.period_end,                            // period_end
        invoice.invoice_pdf,                           // invoice_pdf
        invoice.hosted_invoice_url,                    // hosted_invoice_url
        JSON.stringify(invoice.metadata || {}),        // metadata
        invoice.created,                               // ctime
        now                                            // mtime
      );

      // Check failure count for grace period logic
      const failedCount = await this.paymentDb.await_proc(
        'count_failed_invoices',
        invoice.customer,
        invoice.subscription
      );

      if (failedCount && failedCount[0] && failedCount[0].count >= 3) {
        // After 3 failures: downgrade to free plan
        await this.yp.await_proc('drumate_update_profile', drumateId, JSON.stringify({
          category: 'default'
        }));

        this.warn(`[PAYMENT] Downgraded drumate ${drumateId} to free plan after ${failedCount[0].count} failures`);
        // Send downgrade notification
        try {
          const userData = await this.yp.await_proc('get_user', drumateId);
          await this.sendPaymentData('payment.plan_downgraded', {
            ...userData,
            reason: 'payment_failures',
            failure_count: failedCount[0].count,
            invoice_id: invoice.id,
            downgraded_at: Math.floor(Date.now() / 1000)
          }, drumateId);
        } catch (wsError) {
          this.warn('[PAYMENT] Failed to send downgrade notification:', wsError.message);
        }
      } else {
        this.warn(`[PAYMENT] Payment failed for drumate ${drumateId}, invoice: ${invoice.id} (grace period active)`);
        // Send grace period notification
        try {
          const userData = await this.yp.await_proc('get_user', drumateId);
          await this.sendPaymentData('payment.invoice_failed', {
            ...userData,
            invoice_id: invoice.id,
            failure_count: (failedCount && failedCount[0]) ? failedCount[0].count : 1,
            grace_period: true,
            failed_at: Math.floor(Date.now() / 1000)
          }, drumateId);
        } catch (wsError) {
          this.warn('[PAYMENT] Failed to send invoice failure notification:', wsError.message);
        }
      }

    } catch (error) {
      this.error('[PAYMENT] Error handling invoice.payment_failed:', error);
      throw error;
    }
  }

  /**
  * Handle invoice.payment_action_required event
  * - Payment needs additional authentication (3D Secure)
  * - Save invoice with requires_action status
  * - Send notification to user
  */
  async _handleInvoiceActionRequired(invoice) {
    try {
      this.debug('[PAYMENT] Processing invoice.payment_action_required:', invoice.id);

      const drumateId = invoice.metadata?.drumate_id
        || invoice.lines?.data?.[0]?.metadata?.drumate_id
        || invoice.subscription_details?.metadata?.drumate_id;

      if (!drumateId) {
        this.warn('[PAYMENT][1070] No drumate_id in invoice metadata:', invoice);
        return;
      }

      const priceId = invoice.lines.data[0]?.price?.id;
      let plan = {
        plan_name: 'Unknown',
        quota_category: { category: 'default' },
        storage_quota: 0,
        billing_period: 'monthly'
      };

      if (priceId) {
        const planInfo = await this.paymentDb.await_proc('get_plan_by_price', priceId);
        if (planInfo && planInfo.stripe_price_id) {
          plan = planInfo;
        }
      }

      const now = Math.floor(Date.now() / 1000);

      // Save invoice with requires_action status
      await this.paymentDb.await_proc(
        'create_or_update_invoice',
        invoice.id,
        invoice.customer,
        drumateId,
        invoice.subscription,
        invoice.payment_intent,
        invoice.number,
        invoice.amount_due,
        0,
        invoice.currency,
        'requires_action',                             // status
        plan.plan_name,
        JSON.stringify(plan.quota_category),
        plan.storage_quota,
        plan.billing_period,
        invoice.created,
        invoice.due_date,
        null,
        invoice.period_start,
        invoice.period_end,
        invoice.invoice_pdf,
        invoice.hosted_invoice_url,
        JSON.stringify(invoice.metadata || {}),
        invoice.created,
        now
      );

      this.debug(`[PAYMENT] Payment requires action for drumate ${drumateId}, invoice: ${invoice.id}`);

      // Send WebSocket notification
      try {
        const userData = await this.yp.await_proc('get_user', drumateId);
        await this.sendPaymentData('payment.action_required', {
          ...userData,
          invoice_id: invoice.id,
          payment_intent: invoice.payment_intent,
          action_required_at: Math.floor(Date.now() / 1000)
        }, drumateId);
      } catch (wsError) {
        this.warn('[PAYMENT] Failed to send action required notification:', wsError.message);
      }

    } catch (error) {
      this.error('[PAYMENT] Error handling invoice.payment_action_required:', error);
      throw error;
    }
  }

  /**
   * API: Sync Plans from Stripe
   * Endpoint: POST /payment.sync_plans
   * 
   * Automatically fetch all products and prices from Stripe
   * and update the plan_mapping table
   * 
   * This should be run:
   * - After creating/updating products in Stripe Dashboard
   * - Periodically to keep prices in sync
   * 
   * Output:
   * - synced: number of plans synced
   * - plans: array of synced plan details
   */
  async sync_plans() {
    try {
      if (!this.stripe) {
        return this.output.data({
          status: 'error',
          error: 'stripe_not_configured',
          message: 'Stripe is not configured on server'
        });
      }

      this.debug('[PAYMENT] Starting plan sync from Stripe...');

      // Fetch all products from Stripe
      const products = await this.stripe.products.list({
        active: true,
        expand: ['data.default_price']
      });

      const syncedPlans = [];
      const now = Math.floor(Date.now() / 1000);
      // Process each product
      for (const product of products.data) {
        // Fetch all prices for this product
        const prices = await this.stripe.prices.list({
          product: product.id,
          active: true
        });

        for (const price of prices.data) {
          // Only process recurring prices (subscriptions)
          if (price.type !== 'recurring') {
            this.debug(`[PAYMENT] Skipping one-time price: ${price.id}`);
            continue;
          }

          const category = this._mapProductToCategory(product);
          const storageQuota = this._getStorageQuota(category);

          const billingPeriod = price.recurring.interval; // 'month' or 'year'

          // Insert or update in plan_mapping table
          await this.paymentDb.await_proc(
            'upsert_plan_mapping',
            price.id,                                      // stripe_price_id
            product.id,                                    // stripe_product_id
            product.name,                                  // plan_name
            JSON.stringify({ category: category }),        // quota_category (JSON)
            storageQuota,                                  // storage_quota (bytes)
            billingPeriod,                                 // billing_period
            1,                                             // active
            now,                                           // ctime
            now                                            // mtime
          );

          syncedPlans.push({
            price_id: price.id,
            product_id: product.id,
            product_name: product.name,
            category: category,
            storage_quota: storageQuota,
            billing_period: billingPeriod,
            unit_amount: price.unit_amount,
            currency: price.currency
          });

          this.debug(`[PAYMENT] Synced: ${product.name} (${billingPeriod}) - ${price.id}`);
        }
      }

      this.debug(`[PAYMENT] Plan sync completed. Synced ${syncedPlans.length} plans.`);

      return this.output.data({
        status: 'ok',
        synced: syncedPlans.length,
        plans: syncedPlans
      });

    } catch (error) {
      this.warn('[PAYMENT] Error syncing plans:', error.message);
      return this.output.data({
        status: 'error',
        error: 'sync_failed',
        message: error.message
      });
    }
  }

  /**
   * Map Stripe product to Drumee quota category
   * 
   * Priority order:
   * 1. product.metadata.category (set in Stripe Dashboard)
   * 2. Name-based detection (fallback for legacy products)
   * 3. Default category
   * 
   * @see https://stripe.com/docs/api/metadata
   * @private
   */
  _mapProductToCategory(product) {
    if (product.metadata && product.metadata.category) {
      return product.metadata.category;
    }

    const name = product.name.toLowerCase();

    if (name.includes('enterprise') || name.includes('entreprise')) {
      return 'entreprise';
    }

    if (name.includes('premium')) {
      return 'premium';
    }

    if (name.includes('pro') && !name.includes('premium')) {
      return 'pro';
    }

    if (name.includes('plus')) {
      return 'plus';
    }

    if (name.includes('free') || name.includes('basic')) {
      return 'default';
    }

    this.warn(`[PAYMENT] Unknown product: "${product.name}" (${product.id}), defaulting to 'default'`);
    this.warn(`[PAYMENT] Recommendation: Set metadata.category in Stripe Dashboard for "${product.name}"`);
    return 'default';
  }

  /**
   * Get storage quota in bytes for a category
   * 
   * These are business rules and should live in code (not config)
   * for version control, type safety, and easier testing
   * 
   * @private
   */
  _getStorageQuota(category) {
    const quotas = {
      'default': 20000000000,        // 5GB
      'free': 20000000000,          // 20GB
      'plus': 20000000000,          // 20GB
      'pro': 20000000000,           // 50GB 
      'premium': 50000000000,       // 50GB
      'entreprise': 99000000000     // 99GB
    };

    return quotas[category] || quotas['default'];
  }


}

module.exports = Payment;