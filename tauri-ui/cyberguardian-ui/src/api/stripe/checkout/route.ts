import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);


export async function POST(request: NextRequest) {
  try {
    const { plan } = await request.json();

    const prices: Record<string, { amount: number; devices: number }> = {
      home: { amount: 5000, devices: 1 },      // €50.00
      business: { amount: 10000, devices: 5 }  // €100.00
    };

    if (!prices[plan]) {
      return NextResponse.json(
        { error: 'Invalid plan' },
        { status: 400 }
      );
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'eur',
            product_data: {
              name: `CyberGuardian ${plan.toUpperCase()} License`,
              description: `1-year license for ${prices[plan].devices} device(s)`,
            },
            unit_amount: prices[plan].amount,
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${process.env.NEXT_PUBLIC_BASE_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.NEXT_PUBLIC_BASE_URL}/pricing`,
      metadata: {
        plan,
        max_devices: prices[plan].devices.toString(),
      },
    });

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error('Stripe checkout error:', error);
    return NextResponse.json(
      { error: 'Checkout failed' },
      { status: 500 }
    );
  }
}