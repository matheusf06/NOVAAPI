// Importa as bibliotecas necessárias
import fastify from 'fastify';
import { createClient } from '@supabase/supabase-js';
import 'dotenv/config'; // Carrega as variáveis de ambiente
import fastifyJwt from '@fastify/jwt';
import fastifyCors from '@fastify/cors';
import bcrypt from 'bcryptjs';

// --- CONFIGURAÇÃO DO SUPABASE ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Supabase URL e Key são obrigatórias no arquivo .env');
}
const supabase = createClient(supabaseUrl, supabaseKey);

// --- INICIALIZAÇÃO DO FASTIFY ---
const app = fastify({ logger: true }); // O logger ajuda a ver as requisições no terminal

// --- PLUGINS DO FASTIFY ---
app.register(fastifyCors, { origin: '*' }); // Permite requisições de qualquer origem
app.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'supersecretkeyparadesenvolvimento',
});

// --- DECORATOR DE AUTENTICAÇÃO ---
// Adiciona uma função 'authenticate' para proteger rotas
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
// ROTA DE TESTE
// ==========================================================
app.get('/', () => {
  return { message: 'Bem-vindo à API do Planeta Água! 🌎' };
});

// ==========================================================
// ROTAS DE AUTENTICAÇÃO E USUÁRIOS
// ==========================================================

// Rota de Cadastro (SignUp)
app.post('/signup', async (request, reply) => {
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
});

// Rota de Login
app.post('/login', async (request, reply) => {
  const { email, password } = request.body;
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
  return { user: userResponse, token };
});

// Rota para buscar perfil do usuário (Protegida)
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
// ROTAS DE PRODUTOS (Públicas)
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
// ROTAS DE ENDEREÇOS (Protegidas)
// ==========================================================

// Listar endereços do usuário logado
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

// Adicionar um novo endereço
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

// Deletar um endereço
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
      .eq('user_id', userId); // Garante que o usuário só pode deletar seu próprio endereço

    if (error) return reply.status(500).send({ error: error.message });
    return reply.status(204).send(); // 204 No Content - Sucesso sem corpo de resposta
  }
);

// ==========================================================
// ROTAS DE PEDIDOS (Protegidas)
// ==========================================================

// Criar um novo pedido
app.post(
  '/orders',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { items, total, shipping_address } = request.body; // 'items' deve ser um array: [{ product_id, quantity, price_at_purchase }]

    if (!items || items.length === 0 || !total || !shipping_address) {
      return reply.status(400).send({ error: 'Dados do pedido incompletos.' });
    }

    // 1. Criar o pedido na tabela 'orders'
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

    // 2. Adicionar os itens do pedido na tabela 'order_items'
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
      // Se der erro aqui, idealmente deveríamos deletar o pedido criado para não deixar lixo no banco
      await supabase.from('orders').delete().eq('id', orderData.id);
      return reply.status(500).send({
        error: 'Erro ao salvar os itens do pedido.',
        details: itemsError.message,
      });
    }

    return reply.status(201).send({ order: orderData });
  }
);

// Listar histórico de pedidos do usuário
app.get(
  '/orders',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;

    const { data: orders, error } = await supabase
      .from('orders')
      .select(
        `
      id,
      status,
      total,
      created_at,
      shipping_address,
      order_items (
        quantity,
        price_at_purchase,
        products ( name, image_url )
      )
    `
      )
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) {
      return reply.status(500).send({ error: error.message });
    }

    return { orders };
  }
);

// Adicionar estas rotas ao seu server.js:

// ==========================================================
// ROTAS DE CARTÕES DE CRÉDITO (Protegidas)
// ==========================================================

// Listar cartões do usuário
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

// Adicionar cartão
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
    return reply.status(201).send({ creditCard: data });
  }
);

// Deletar cartão
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
// ATUALIZAR ROTA DE ENDEREÇOS
// ==========================================================

// Editar endereço
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
        zip_code: zipCode, // Conversão de camelCase para snake_case
      })
      .eq('id', id)
      .eq('user_id', userId)
      .select()
      .single();

    if (error) return reply.status(500).send({ error: error.message });

    // Retornar no formato camelCase
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

// ==========================================================
// ROTA PARA PROCESSAR PEDIDO
// ==========================================================

app.post(
  '/orders/process',
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userId = request.user.sub;
    const { items, total, addressId, paymentMethod } = request.body;

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
      return reply.status(500).send({
        error: 'Erro ao criar o pedido.',
        details: orderError.message,
      });
    }

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
      await supabase.from('orders').delete().eq('id', orderData.id);
      return reply.status(500).send({
        error: 'Erro ao salvar os itens do pedido.',
        details: itemsError.message,
      });
    }

    return reply.status(201).send({
      order: orderData,
      message: 'Pedido criado com sucesso!',
    });
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
