// Importa as bibliotecas necessárias
import fastify from 'fastify';
import { createClient } from '@supabase/supabase-js';
import 'dotenv/config';
import fastifyJwt from '@fastify/jwt';
import fastifyCors from '@fastify/cors';
import bcrypt from 'bcryptjs';
import { MercadoPagoConfig, Payment, Preference } from 'mercadopago';

// --- CONFIGURAÇÃO DO SUPABASE ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Supabase URL e Key são obrigatórias no arquivo .env');
}
const supabase = createClient(supabaseUrl, supabaseKey);

// --- CONFIGURAÇÃO DO MERCADO PAGO ---
const mercadoPagoClient = new MercadoPagoConfig({
  accessToken: process.env.MERCADO_PAGO_ACCESS_TOKEN || 'APP_USR-6689963437415441-100113-f9c37f02b5fdd7c4160abfd8c572af88-2725494890',
  options: { timeout: 5000 }
});

const payment = new Payment(mercadoPagoClient);
const preference = new Preference(mercadoPagoClient);

// --- INICIALIZAÇÃO DO FASTIFY ---
const app = fastify({ logger: true });

// --- PLUGINS DO FASTIFY ---
app.register(fastifyCors, { origin: '*' });
app.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'supersecretkeyparadesenvolvimento',
});

// --- DECORATOR DE AUTENTICAÇÃO ---
app.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply
      .status(401)
      .send({ error: 'Não autorizado. Token inválido ou expirado.' });
  }
});

// ==========================================================
// ROTA DE TESTE E HEALTH CHECK
// ==========================================================
app.get('/', () => {
  return { message: 'Bem-vindo à API do Planeta Água! 🌎' };
});

app.get('/health', () => {
  return { 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    message: 'API funcionando normalmente'
  };
});

// ==========================================================
// ROTAS DE AUTENTICAÇÃO E USUÁRIOS
// ==========================================================

app.post('/signup', async (request, reply) => {
  try {
    const { name, email, password } = request.body;
    
    if (!name || !email || !password) {
      return reply
        .status(400)
        .send({ error: 'Nome, email e senha são obrigatórios.' });
    }
    
    const password_hash = await bcrypt.hash(password, 8);
    const { data, error } = await supabase
      .from('users')
      .insert([{ name, email, password_hash }])
      .select('id, name, email, created_at')
      .single();

    if (error) {
      if (error.code === '23505') {
        return reply.status(409).send({ error: 'Este email já está em uso.' });
      }
      return reply
        .status(500)
        .send({ error: 'Erro ao criar usuário.', details: error.message });
    }
    
    return reply.status(201).send({ user: data });
  } catch (error) {
    console.error('Erro no signup:', error);
    return reply.status(500).send({ error: 'Erro interno do servidor.' });
  }
});

app.post('/login', async (request, reply) => {
  try {
    const { email, password } = request.body;
    
    if (!email || !password) {
      return reply.status(400).send({ error: 'Email e senha são obrigatórios.' });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
      
    if (error || !user) {
      return reply.status(401).send({ error: 'Email ou senha inválidos.' });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return reply.status(401).send({ error: 'Email ou senha inválidos.' });
    }
    
    const token = app.jwt.sign(
      { name: user.name, email: user.email },
      { sub: user.id, expiresIn: '7d' }
    );
    
    const { password_hash, ...userResponse } = user;
    
    const response = { 
      user: userResponse, 
      token 
    };
    
    console.log('Login successful for:', email);
    
    return reply.status(200).send(response);
    
  } catch (error) {
    console.error('Erro no login:', error);
    return reply.status(500).send({ error: 'Erro interno do servidor.' });
  }
});

app.get(
  '/profile',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, email, phone')
      .eq('id', userId)
      .single();
    if (error || !user) {
      return reply.status(404).send({ error: 'Usuário não encontrado.' });
    }
    return { user };
  }
);

// ==========================================================
// ROTAS DE PRODUTOS
// ==========================================================
app.get('/products', async () => {
  const { data, error } = await supabase
    .from('products')
    .select('*')
    .order('name');
  if (error) throw new Error(error.message);
  return { products: data };
});

app.get('/products/:id', async (request, reply) => {
  const { id } = request.params;
  const { data, error } = await supabase
    .from('products')
    .select('*')
    .eq('id', id)
    .single();
  if (error || !data) {
    return reply.status(404).send({ error: 'Produto não encontrado.' });
  }
  return { product: data };
});

// ==========================================================
// ROTAS DE ENDEREÇOS
// ==========================================================

app.get(
  '/addresses',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { data, error } = await supabase
      .from('addresses')
      .select('*')
      .eq('user_id', userId);
    if (error) return reply.status(500).send({ error: error.message });
    return { addresses: data };
  }
);

app.post(
  '/addresses',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { street, neighborhood, city, state, zip_code } = request.body;

    if (!street || !neighborhood || !city || !state || !zip_code) {
      return reply
        .status(400)
        .send({ error: 'Todos os campos do endereço são obrigatórios.' });
    }

    const { data, error } = await supabase
      .from('addresses')
      .insert([
        { user_id: userId, street, neighborhood, city, state, zip_code },
      ])
      .select()
      .single();

    if (error) return reply.status(500).send({ error: error.message });
    return reply.status(201).send({ address: data });
  }
);

app.put(
  '/addresses/:id',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { id } = request.params;
    const { street, neighborhood, city, state, zipCode } = request.body;

    if (!street || !neighborhood || !city || !state || !zipCode) {
      return reply.status(400).send({
        error: 'Todos os campos do endereço são obrigatórios.',
      });
    }

    const { data, error } = await supabase
      .from('addresses')
      .update({
        street,
        neighborhood,
        city,
        state,
        zip_code: zipCode,
      })
      .eq('id', id)
      .eq('user_id', userId)
      .select()
      .single();

    if (error) return reply.status(500).send({ error: error.message });

    const formattedAddress = {
      id: data.id,
      street: data.street,
      neighborhood: data.neighborhood,
      city: data.city,
      state: data.state,
      zipCode: data.zip_code,
    };

    return { address: formattedAddress };
  }
);

app.delete(
  '/addresses/:id',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { id } = request.params;

    const { error } = await supabase
      .from('addresses')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (error) return reply.status(500).send({ error: error.message });
    return reply.status(204).send();
  }
);

// ==========================================================
// ROTAS DE CARTÕES DE CRÉDITO
// ==========================================================

app.get(
  '/credit-cards',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { data, error } = await supabase
      .from('credit_cards')
      .select('id, brand, last4, expiry')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) return reply.status(500).send({ error: error.message });
    return { creditCards: data };
  }
);

app.post(
  '/credit-cards',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { brand, last4, expiry } = request.body;

    if (!brand || !last4 || !expiry) {
      return reply.status(400).send({
        error: 'Brand, last4 e expiry são obrigatórios.',
      });
    }

    const { data, error } = await supabase
      .from('credit_cards')
      .insert([{ user_id: userId, brand, last4, expiry }])
      .select()
      .single();

    if (error) return reply.status(500).send({ error: error.message });
    return reply.status(201).send({ card: data });
  }
);

app.delete(
  '/credit-cards/:id',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { id } = request.params;

    const { error } = await supabase
      .from('credit_cards')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (error) return reply.status(500).send({ error: error.message });
    return reply.status(204).send();
  }
);

// ==========================================================
// ROTAS DE PAGAMENTO COM MERCADO PAGO
// ==========================================================

// Criar preferência de pagamento (para Checkout Pro ou PIX)
app.post(
  '/payments/create-preference',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    try {
      const userId = request.user.sub;
      const { items, payer } = request.body;

      if (!items || items.length === 0) {
        return reply.status(400).send({ error: 'Items são obrigatórios.' });
      }

      // Buscar dados do usuário
      const { data: user } = await supabase
        .from('users')
        .select('email, name, phone')
        .eq('id', userId)
        .single();

      // Formatar items para o Mercado Pago
      const mpItems = items.map(item => ({
        title: item.name || item.title,
        quantity: item.quantity,
        unit_price: parseFloat(item.price),
        currency_id: 'BRL'
      }));

      const body = {
        items: mpItems,
        payer: {
          email: payer?.email || user?.email || 'teste@teste.com',
          name: payer?.name || user?.name,
          phone: {
            area_code: payer?.phone?.substring(0, 2) || '11',
            number: payer?.phone?.substring(2) || '999999999'
          }
        },
        back_urls: {
          success: process.env.FRONTEND_URL + '/payment/success',
          failure: process.env.FRONTEND_URL + '/payment/failure',
          pending: process.env.FRONTEND_URL + '/payment/pending'
        },
        auto_return: 'approved',
        notification_url: process.env.API_URL + '/payments/webhook',
        statement_descriptor: 'Planeta Água',
        external_reference: `user_${userId}_${Date.now()}`
      };

      const preferenceResponse = await preference.create({ body });

      return reply.status(201).send({
        preferenceId: preferenceResponse.id,
        initPoint: preferenceResponse.init_point,
        sandboxInitPoint: preferenceResponse.sandbox_init_point
      });

    } catch (error) {
      console.error('Erro ao criar preferência:', error);
      return reply.status(500).send({ 
        error: 'Erro ao criar preferência de pagamento.',
        details: error.message 
      });
    }
  }
);

// Processar pagamento com cartão de crédito
app.post(
  '/payments/process',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    try {
      const userId = request.user.sub;
      const { 
        token, 
        installments, 
        items, 
        addressId,
        paymentMethodId = 'master'
      } = request.body;

      if (!token || !items || items.length === 0 || !addressId) {
        return reply.status(400).send({ error: 'Dados incompletos.' });
      }

      // Buscar usuário e endereço
      const { data: user } = await supabase
        .from('users')
        .select('email, name')
        .eq('id', userId)
        .single();

      const { data: address } = await supabase
        .from('addresses')
        .select('*')
        .eq('id', addressId)
        .eq('user_id', userId)
        .single();

      if (!address) {
        return reply.status(404).send({ error: 'Endereço não encontrado.' });
      }

      // Calcular total
      const total = items.reduce((sum, item) => 
        sum + (parseFloat(item.price) * item.quantity), 0
      );

      const body = {
        transaction_amount: total,
        token: token,
        installments: installments || 1,
        payment_method_id: paymentMethodId,
        payer: {
          email: user.email,
          identification: {
            type: 'CPF',
            number: '12345678909' // Em produção, você deve coletar isso
          }
        },
        description: `Compra Planeta Água - ${items.length} item(ns)`,
        external_reference: `user_${userId}_${Date.now()}`,
        statement_descriptor: 'Planeta Água'
      };

      const paymentResponse = await payment.create({ body });

      // Se pagamento aprovado, criar pedido
      if (paymentResponse.status === 'approved') {
        const shippingAddress = `${address.street}, ${address.neighborhood}, ${address.city} - ${address.state}`;

        const { data: orderData } = await supabase
          .from('orders')
          .insert([{
            user_id: userId,
            total,
            shipping_address: shippingAddress,
            status: 'confirmed',
            payment_id: paymentResponse.id.toString()
          }])
          .select()
          .single();

        // Adicionar items do pedido
        const orderItems = items.map(item => ({
          order_id: orderData.id,
          product_id: item.id,
          quantity: item.quantity,
          price_at_purchase: item.price
        }));

        await supabase.from('order_items').insert(orderItems);

        return reply.status(201).send({
          payment: paymentResponse,
          order: orderData,
          message: 'Pagamento aprovado e pedido criado!'
        });
      }

      return reply.status(200).send({
        payment: paymentResponse,
        message: 'Pagamento processado.'
      });

    } catch (error) {
      console.error('Erro ao processar pagamento:', error);
      return reply.status(500).send({ 
        error: 'Erro ao processar pagamento.',
        details: error.message 
      });
    }
  }
);

// Webhook para receber notificações do Mercado Pago
app.post('/payments/webhook', async (request, reply) => {
  try {
    const { type, data } = request.body;

    console.log('Webhook recebido:', { type, data });

    if (type === 'payment') {
      const paymentId = data.id;
      
      // Buscar detalhes do pagamento
      const paymentInfo = await payment.get({ id: paymentId });
      
      console.log('Status do pagamento:', paymentInfo.status);

      // Atualizar pedido no banco com base no status
      if (paymentInfo.external_reference) {
        const { error } = await supabase
          .from('orders')
          .update({ 
            status: paymentInfo.status === 'approved' ? 'confirmed' : 'pending',
            payment_id: paymentId.toString()
          })
          .eq('payment_id', paymentId.toString());

        if (error) {
          console.error('Erro ao atualizar pedido:', error);
        }
      }
    }

    return reply.status(200).send({ received: true });

  } catch (error) {
    console.error('Erro no webhook:', error);
    return reply.status(200).send({ received: true }); // Sempre retornar 200 para o MP
  }
});

// ==========================================================
// ROTAS DE PEDIDOS
// ==========================================================

app.post(
  '/orders',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { items, total, shipping_address } = request.body;

    if (!items || items.length === 0 || !total || !shipping_address) {
      return reply.status(400).send({ error: 'Dados do pedido incompletos.' });
    }

    const { data: orderData, error: orderError } = await supabase
      .from('orders')
      .insert([{ user_id: userId, total, shipping_address }])
      .select()
      .single();

    if (orderError)
      return reply.status(500).send({
        error: 'Erro ao criar o pedido.',
        details: orderError.message,
      });

    const orderItems = items.map((item) => ({
      order_id: orderData.id,
      product_id: item.product_id,
      quantity: item.quantity,
      price_at_purchase: item.price_at_purchase,
    }));

    const { error: itemsError } = await supabase
      .from('order_items')
      .insert(orderItems);

    if (itemsError) {
      await supabase.from('orders').delete().eq('id', orderData.id);
      return reply.status(500).send({
        error: 'Erro ao salvar os itens do pedido.',
        details: itemsError.message,
      });
    }

    return reply.status(201).send({ order: orderData });
  }
);

app.get(
  '/orders',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;

    const { data: orders, error } = await supabase
      .from('orders')
      .select(`
        id,
        status,
        total,
        created_at,
        shipping_address,
        payment_id,
        order_items (
          quantity,
          price_at_purchase,
          products ( name, image_url )
        )
      `)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      return reply.status(500).send({ error: error.message });
    }

    return { orders };
  }
);

// ==========================================================
// ROTA PARA PROCESSAR PEDIDO (simplificado)
// ==========================================================

app.post(
  '/orders/process',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    try {
      const userId = request.user.sub;
      const { items, total, addressId, paymentMethod, cardId } = request.body;

      console.log('📦 Processando pedido:', { userId, total, addressId, paymentMethod });

      if (!items || items.length === 0 || !total || !addressId) {
        return reply.status(400).send({ error: 'Dados do pedido incompletos.' });
      }

      // Buscar endereço
      const { data: address, error: addressError } = await supabase
        .from('addresses')
        .select('*')
        .eq('id', addressId)
        .eq('user_id', userId)
        .single();

      if (addressError || !address) {
        console.error('Erro ao buscar endereço:', addressError);
        return reply.status(404).send({ error: 'Endereço não encontrado.' });
      }

      // Formato do endereço para shipping_address
      const shippingAddress = `${address.street}, ${address.neighborhood}, ${address.city} - ${address.state}`;

      // Criar pedido
      const { data: orderData, error: orderError } = await supabase
        .from('orders')
        .insert([
          {
            user_id: userId,
            total,
            shipping_address: shippingAddress,
            status: paymentMethod === 'PIX' ? 'pending' : 'confirmed',
          },
        ])
        .select()
        .single();

      if (orderError) {
        console.error('Erro ao criar pedido:', orderError);
        return reply.status(500).send({
          error: 'Erro ao criar o pedido.',
          details: orderError.message,
        });
      }

      console.log('✅ Pedido criado:', orderData.id);

      // Adicionar items
      const orderItems = items.map((item) => ({
        order_id: orderData.id,
        product_id: item.id,
        quantity: item.quantity,
        price_at_purchase: item.price,
      }));

      const { error: itemsError } = await supabase
        .from('order_items')
        .insert(orderItems);

      if (itemsError) {
        console.error('Erro ao salvar items:', itemsError);
        await supabase.from('orders').delete().eq('id', orderData.id);
        return reply.status(500).send({
          error: 'Erro ao salvar os itens do pedido.',
          details: itemsError.message,
        });
      }

      console.log('✅ Items salvos com sucesso');

      return reply.status(201).send({
        order: orderData,
        message: 'Pedido criado com sucesso!',
      });
    } catch (error) {
      console.error('💥 Erro crítico ao processar pedido:', error);
      return reply.status(500).send({
        error: 'Erro ao processar pedido.',
        details: error.message,
      });
    }
  }
);

// ==========================================================
// INICIALIZAÇÃO DO SERVIDOR
// ==========================================================
const start = async () => {
  try {
    await app.listen({
      host: '0.0.0.0',
      port: process.env.PORT ? Number(process.env.PORT) : 3333,
    });
    console.log(
      `🚀 Servidor HTTP rodando na porta ${app.server.address().port}`
    );
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();

